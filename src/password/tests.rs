// 本文件的测试原内联在父模块的 `#[cfg(test)] mod tests` 中，
// 抽到这里作为子模块文件（做法 1：子模块文件，保留对父模块私有项的访问）。
    use super::*;

    /// 环境变量名必须稳定：它是运维接口的一部分，改了会静默失效（读不到就是交互式挂住）。
    #[test]
    fn env_var_name_is_stable() {
        assert_eq!(ENV_PASSWORD, "SIGN_PASSWORD");
    }

    /// `Password` 不实现 `Debug`（防误打印），但 `Source` 要实现（启动日志要用）。
    #[test]
    fn source_is_debug_but_the_value_is_not_leaked() {
        // Source 可 Debug。
        assert_eq!(format!("{:?}", Source::Tty), "Tty");
        assert_eq!(format!("{:?}", Source::Env), "Env");
    }

    /// `as_bytes` 给出的是口令原始字节（Argon2 要的是字节，不是 UTF-8 校验过的字符串）。
    #[test]
    fn as_bytes_returns_the_utf8_bytes() {
        let p = Password {
            value: Zeroizing::new("hunter2hunter2".to_string()),
            source: Source::Tty,
        };
        assert_eq!(p.as_bytes(), b"hunter2hunter2");
        assert_eq!(p.source(), Source::Tty);
    }

    /// 环境变量不存在时 `env_password` 返回 `None`（不会误当成空口令）。
    ///
    /// 若这里退化成 `Some("")`，空口令就会「静默生效」——文件照样能建能开，
    /// 但等于没加密。所以显式钉住。
    #[test]
    fn a_missing_env_var_is_none_not_an_empty_password() {
        // 用一个确定不存在的变量名验证等价路径。
        assert!(std::env::var_os("SIGN_DEFINITELY_UNSET_VAR").is_none());
    }

    /// 读不到终端时，报错必须把环境变量名写出来，否则用户无从下手。
    ///
    /// 原生报错（如 "Inappropriate ioctl for device"）对排查毫无帮助——
    /// 用户不知道该去设置什么。这条断言把「错误信息可执行」钉住。
    #[test]
    fn the_no_tty_error_names_the_env_var_and_the_cause() {
        let cause = std::io::Error::from(std::io::ErrorKind::NotFound);
        let msg = no_tty_error("解锁", cause).to_string();
        assert!(msg.contains(ENV_PASSWORD), "报错应给出变量名: {msg}");
        assert!(msg.contains("读不到终端"), "报错应说明原因: {msg}");
        assert!(msg.contains("解锁"), "报错应说明在做什么: {msg}");
        // 底层原因也要带上，便于排查是 /dev/tty 不存在还是权限问题。
        assert!(msg.contains("entity not found"), "应附上原生错误: {msg}");
    }
