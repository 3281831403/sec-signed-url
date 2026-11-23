给客户发的下载链接被转发到了外网论坛，一年后那条链接还能打开：签名串按字典插入顺序拼接，字段顺序一变签名就不同；签名串不含请求方法，换个方法就能复用同一签名；签名串不含路径，同一签名可以跨文件使用；签名比较用普通等号而不是恒定时间比较；有效期只判断是否已过期，不校验上限；有效期用字符串比较时间戳，位数不同时顺序出错；路径校验只看字符串前缀，同名前缀目录被放行；地址绑定只做精确比较，网段配置完全无效；策略校验不检查有效期上限；批量校验复用同一个规范化串，后一个请求会命中前一个请求的签名。engine/url/sign.py 是核心，tests/url/test_sign.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式

在仓库根目录执行：

python -m pytest tests -q

基线输出为 15 failed，没有 error。15 个测试全部位于 tests/url/test_sign.py，测试不可修改；所有修复只能发生在 engine/url/sign.py。

字段表

安全：高
漏洞检测与攻防：是
Bugfix：是
 3, pytest

目录结构

sec-signed-url/
  README.md
  conftest.py
  engine/__init__.py
  engine/url/__init__.py
  engine/url/sign.py
  tests/url/test_sign.py

engine 嵌套布局说明

engine 与 engine/url 都是普通包，engine/url/sign.py 是唯一实现文件，不拆分辅助模块。tests/url/test_sign.py 从 engine.url.sign 导入 8 个公开函数。仓库根的 conftest.py 把仓库根目录加入 sys.path，因此无需安装包，也无需设置环境变量。

修复提示

按题面列出的顺序逐个修复 10 个缺陷，实现 8 个函数。签名使用 HMAC-SHA256，十六进制小写输出；时间戳为整数秒并由调用方显式传入，不使用随机数，不联网。修复完成后同一命令应显示 15 passed。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |
