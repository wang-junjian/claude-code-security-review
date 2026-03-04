# 安全评估结果查看系统

一个动态的Web界面，用于查看安全评估结果。

## 功能特性

- **实时解析**：服务器启动时会实时扫描 `eval_results/` 目录中的评估结果文件
- **动态显示**：无需手动更新 `results.json` 文件，刷新浏览器即可看到最新结果
- **完整功能**：
  - 按类型（PR/仓库）、仓库名称、PR号筛选
  - 搜索功能（支持仓库名和PR号）
  - 显示评估结果的详细信息
  - 按严重程度（HIGH/MEDIUM/LOW）标记颜色
  - 响应式设计，支持多种屏幕尺寸

## 使用方法

### 1. 启动服务器

```bash
cd web
node server.js
```

服务器将运行在 `http://localhost:8081`

### 2. 访问Web界面

在浏览器中打开 `http://localhost:8081`

### 3. 查看评估结果

- 服务器会自动读取 `../eval_results/` 目录中的所有评估结果
- 支持的文件名格式：
  - PR评估：`pr_仓库名_PR号.json`（如：`pr_anthropics_claude-code-security-review_70.json`）
  - 仓库评估：`repo_仓库名.json`（如：`repo_wang-junjian_LingMaster.json`）

### 4. 停止服务器

按 `Ctrl+C` 停止服务器

## 技术说明

- **服务器**：Node.js内置HTTP服务器
- **API**：提供 `/api/results` 端点返回JSON格式的评估结果
- **前端**：HTML5 + CSS3 + JavaScript（ES6+）
- **依赖**：无外部依赖（使用Node.js内置模块）

## 项目结构

```
.
├── web/
│   ├── index.html       # Web界面
│   ├── server.js        # 服务器
│   └── README.md        # 本说明文件
└── eval_results/        # 安全评估结果（位于项目根目录）
    └── *.json           # 评估结果文件
```
