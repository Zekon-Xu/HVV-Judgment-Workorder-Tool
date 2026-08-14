# 待解析文件格式示例

这些文件用于展示本工具支持的输入结构，不是项目配置包。字段名可以按实际平台调整，但建议保留以下语义：

- `time` / 时间：告警发生时间，建议 `YYYY-MM-DD HH:MM:SS`。
- `attack_ip` / 攻击IP：源地址或攻击者地址。
- `target_ip` / 目标IP：目的、受害或被攻击地址。
- `xff` / XFF：代理链来源地址，可为空；多个地址用逗号分隔。
- `domain_url` / 域名URL：URL、域名或 IOC，可为空。
- `alert_level` / 告警级别：高危、中危或低危。
- `attack_name` / 攻击名称：平台规则或告警名称。
- `event_type` / 事件类型：攻击类型分类。
- `attack_result` / 攻击结果：成功、失败、企图或已拦截。

不要把探针、平台或数据源设备 IP 填入攻击IP。Excel、CSV 可以一行一条告警；TXT、JSON、XML、HTML 示例均可直接拖入工具验证。
