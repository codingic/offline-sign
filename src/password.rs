//! 启动时的口令交互：从终端读口令，**关闭回显**。
//!
//! # 为什么单独一个模块
//!
//! 读口令看着只有几行，但有两个坑必须集中处理，散落在 `main` 里迟早漏掉一个：
//!
//! 1. **回显**。用 `std::io::stdin().read_line()` 读口令，输入的字符会直接打印在
//!    屏幕上、并留在终端回滚缓冲区里；若再被 `script`/录屏/日志采集，口令即泄露。
//!    `rpassword` 走 termios 关掉 `ECHO`，跨平台处理了 Windows console。
//! 2. **明文存活时间**。读进来的 `String` 会一直躺在堆上，直到被覆写；进程 core dump
//!    或换出到 swap 都能捞到。所以一律包成 `Zeroizing<String>`——离开作用域即清零。
//!
//! # 无 TTY 环境
//!
//! 后台运行（systemd / nohup / CI）时没有终端可交互，读口令会直接失败。
//! 这种情况从环境变量 `SIGN_PASSWORD` 取，并在日志里**显式说明**来源——
//! 静默回落会让运维以为有交互式提示，结果进程卡死。

use anyhow::{bail, anyhow};
use zeroize::Zeroizing;

/// 环境变量名：无 TTY 时的口令来源。
pub const ENV_PASSWORD: &str = "SIGN_PASSWORD";

/// 最小口令长度。
///
/// 设下限是因为**口令是本系统唯一的防线**：keystore 文件可以被拷走离线暴破，
/// 短口令在 GPU 上几秒就破。宁可启动时多敲几个字符。
pub const MIN_LEN: usize = 8;

// 编译期就把取值卡住，而不是等运行时的 `assert!`：
// 这两个数是**安全策略**而非实现细节，写错不该等到测试才发现——
// `const` 块里的 `assert!` 在编译期求值，改坏了直接编译不过。
const _: () = {
    assert!(MIN_LEN >= 8, "短于 8 位在现代 GPU 上撑不住离线暴破");
    assert!(MIN_LEN <= 32, "超过 32 位会逼用户把口令写下来，反而更不安全");
};

/// 口令来源，仅用于启动日志——让用户知道口令是怎么进来的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// 终端交互输入（回显已关闭）。
    Tty,
    /// 环境变量 `SIGN_PASSWORD`。
    Env,
}

/// 读口令的结果：值 + 来源。值始终被 `Zeroizing` 包裹。
pub struct Password {
    value: Zeroizing<String>,
    source: Source,
}

impl Password {
    /// 取口令字节（交给 Argon2 派生）。
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
    /// 来源，用于启动日志。
    pub fn source(&self) -> Source {
        self.source
    }
}

/// 首次初始化：要求输入两次并校验一致。
///
/// 二次确认不是为了安全，是为了**防手滑**——口令无法找回，敲错一次就永久锁死自己的私钥。
pub fn prompt_new() -> anyhow::Result<Password> {
    if let Some(p) = env_password() {
        // 环境变量路径下没法「确认」，直接采信，但把长度校验照样跑一遍。
        if p.len() < MIN_LEN {
            bail!("环境变量 {ENV_PASSWORD} 里的口令短于 {MIN_LEN} 个字符");
        }
        return Ok(Password { value: p, source: Source::Env });
    }
    // 循环直到「长度达标」且「两次一致」：口令无法找回，防手滑比省事重要。
    loop {
        let first = Zeroizing::new(
            rpassword::prompt_password("新口令（至少 8 字符，无法找回）: ")
                .map_err(|e| no_tty_error("设置新口令", e))?,
        );
        if first.len() < MIN_LEN {
            eprintln!("  口令太短：至少 {MIN_LEN} 个字符。");
            continue;
        }
        let second = Zeroizing::new(
            rpassword::prompt_password("再输一次以确认: ")
                .map_err(|e| no_tty_error("确认口令", e))?,
        );
        // `Zeroizing<String>` 之间比较会走 `Deref` 到 `String` 的 `PartialEq`，
        // 两边都在作用域结束时清零，不会留下明文副本。
        if first != second {
            eprintln!("  两次输入不一致，请重来。");
            continue;
        }
        return Ok(Password { value: first, source: Source::Tty });
    }
}

/// 已存在 keystore：只问一次。口令错由 `vault` 报错、调用方决定是否重试。
pub fn prompt_existing() -> anyhow::Result<Password> {
    if let Some(p) = env_password() {
        return Ok(Password { value: p, source: Source::Env });
    }
    let p = Zeroizing::new(
        rpassword::prompt_password("keystore 口令: ").map_err(|e| no_tty_error("解锁 keystore", e))?,
    );
    Ok(Password { value: p, source: Source::Tty })
}

/// 从环境变量取口令（已包 `Zeroizing`）。
///
/// **刻意不去 `remove_var`**：Rust 2024 起 `remove_var` 是 `unsafe`
/// （并发读写进程环境块有数据竞争，测试并行跑时确实不成立），而本程序不派生子进程，
/// 摘掉它换来的收益为零。
///
/// 代价必须说清：Linux 上同一用户的其他进程可以读 `/proc/<pid>/environ` 看到它，
/// 所以环境变量口令只适合「机器本身可信」的场景（个人开发机、独占容器）。
fn env_password() -> Option<Zeroizing<String>> {
    let raw = std::env::var(ENV_PASSWORD).ok()?;
    Some(Zeroizing::new(raw))
}

/// 读不到终端时的报错文案。
///
/// **为什么不再预先检查 `stdin().is_terminal()`**：那与 `rpassword` 实际读取的
/// `/dev/tty` 不是同一条流，两者会给出矛盾的答案——比如 `echo x | ./sign` 时
/// stdin 不是终端（预检查拒绝），但用户明明坐在终端前、/dev/tty 可读（本可以提示）。
/// 反过来 stdin 是终端却读不到 /dev/tty 时，预检查放行、读取才失败，报错就来晚了。
///
/// 所以改成**先让 `rpassword` 自己试**，失败了再翻译成人话：
/// 判断与读取用的是同一个动作，不可能再有分歧。
fn no_tty_error(what: &str, cause: std::io::Error) -> anyhow::Error {
    anyhow!(
        "需要交互式输入口令才能{what}，但读不到终端（{cause}）。\n\
         \n\
         两种办法：\n\
         \x20 1. 在终端里直接运行本程序；\n\
         \x20 2. 设置环境变量 {ENV_PASSWORD}（注意：同一 shell 的其他进程可通过 /proc 读到它）。"
    )
}

#[cfg(test)] mod tests;
