//! 请求计时：把 `std::time::Instant` 包一层，给各 handler 一个干净的
//! 「开始计时 / 取耗时」口子。
//!
//! 为什么单独成文件：计时是横切所有 handler 的基建，与路由、签名逻辑无关；
//! 抽到这里后 `main.rs` 不再需要 `use std::time::Instant`，handler 里只剩
//! `let timer = Timer::start(); ... ok(data, &timer)` 这种一眼能懂的调用，
//! `Envelope.took_ms` 的毫秒数也只在这里算一次。

use std::time::Instant;

/// 一次请求的计时器。
///
/// 在 handler 入口 `Timer::start()`，结束时把 `&self` 传给 `ok` / `err`，
/// 由它们读出 [`Timer::elapsed_ms`] 填进 `Envelope.took_ms`。
pub struct Timer {
    /// 起点。`Instant` 是单调时钟，适合量「耗时」而非「墙钟时间」。
    start: Instant,
}

impl Timer {
    /// 记下当前时刻作为计时起点。
    ///
    /// 语法说明：`Self` 在关联函数里指代「当前类型」(`Timer`)，
    /// 比写死 `Timer` 更利于后续改名——改结构体名时这里不用跟着改。
    pub fn start() -> Self {
        Self { start: Instant::now() }
    }

    /// 距起点的毫秒数，用于 `Envelope.took_ms`。
    ///
    /// 语法说明：`elapsed()` 返回 `Duration`；`as_millis()` 给 `u128`，
    /// 转 `u64` 是因为 `took_ms` 字段就是 `u64`，且单次请求耗时远不会超过 `u64::MAX` 毫秒。
    /// 这里集中做一次转型，调用方拿到的就是现成的 `u64`，不必每处都 `as u64`。
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}
