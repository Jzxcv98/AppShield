# 参与开发

请用测试账号、临时目录和随机生成的标记复现问题。提 issue 时写明系统版本、引擎版本、合成测试的操作及观察结果。公开报告可用相对路径，如 `fixtures/shared/sample.txt`。原始日志、聊天截图、证书和机器配置应保存在工作区的 `.local/` 中。

从仓库根目录运行以下检查。需要 Git 和 Python 3，可直接使用标准库。

```sh
python -m unittest discover -s tests/privacy
python tools/check_public_tree.py
```

提交前可以用 `python tools/check_public_tree.py --staged` 检查 Git 索引中的实际版本，也可以用 `git config --local core.hooksPath .githooks` 启用相同的提交钩子。检查覆盖若干常见的本机路径和凭据格式，公开前仍应阅读暂存的差异。Git 会单独记录作者姓名和邮箱，可用 `git config --local user.name "Public Alias"` 和 `git config --local user.email "contributor@example.invalid"` 为此仓库设置公开署名。

涉及隔离规则时，请报告程序在宿主、受限和授权三种条件下分别看到了什么。可以在独立测试环境中运行真实客户端，公开记录只需说明版本、结果与限制。

提交到本项目的原创贡献采用 GPL-3.0-only。第三方组件请先注明来源、版本和许可证。
