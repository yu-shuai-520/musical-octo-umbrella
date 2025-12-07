# 数字签约管理系统

基于区块链技术的智能合约数字签约平台。

## 功能特性

- ✅ 用户注册与管理
- ✅ 合同创建与存储
- ✅ 数字签名验证
- ✅ 合同状态跟踪
- ✅ 真实性验证
- ✅ 去中心化存储

## 技术栈

- **前端**: HTML5, CSS3, JavaScript, Bootstrap 5
- **区块链**: Solidity, Web3.js
- **开发框架**: Truffle Suite
- **测试网络**: Ganache

## 快速开始

### 环境要求

- Node.js >= 14.0.0
- npm >= 6.0.0
- Git

### 安装步骤

1. 安装依赖

```powershell
npm install
```

2. 本地开发（启动静态 dev server）

```powershell
npm run dev
```

3. 编译并部署到本地开发网络（需先启动 Ganache），随后把 artifact 复制到 `src/js`

```powershell
npx truffle compile
npx truffle migrate --network development
node .\scripts\build.js
```

4. 便捷脚本

- 一键迁移并复制 artifact:

```powershell
npm run migrate-and-build
```

- 运行前端 E2E 注册/登录测试（需要 dev server 在 3000）：

```powershell
npm run e2e
```