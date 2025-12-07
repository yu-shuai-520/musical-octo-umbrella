// Marker that this script was loaded
window.__digsig_script_loaded = true;
window.__digsig_init_error = null;

class DigitalSignatureApp {
    constructor() {
        this.web3 = null;
        this.contract = null;
        this.accounts = [];
        this.currentAccount = null;
        this.txHistory = [];
        this.settings = {
            contractAddress: null,
            rpcProvider: null
        };
        
        this.init();
    }

    async init() {
        // 加载用户保存的设置（如合约地址 / RPC）
        await this.loadSettings();
        await this.loadWeb3();
        // 全局捕获未处理的 promise rejection（例如媒体 play() 被立即 pause 导致的 AbortError）
        try {
            window.addEventListener('unhandledrejection', (ev) => {
                try {
                    const r = ev && ev.reason;
                    if (!r) return;
                    const msg = (r && r.message) ? r.message : String(r);
                    // 常见浏览器在 media.play() 被中断时抛出的信息
                    if (r.name === 'AbortError' || msg.indexOf('play() request was interrupted') >= 0) {
                        console.debug('Ignored media AbortError:', r);
                        // 阻止浏览器把它当作未捕获错误展示
                        ev.preventDefault && ev.preventDefault();
                    }
                } catch (e) {
                    // 忽略监听器内部错误
                }
            });
        } catch (e) {}
        // 如果用户开启了自动会话创建，并且当前没有本地会话，则尝试使用钱包创建简易会话
        try {
            const sessionRaw = localStorage.getItem('digsig_session');
            if (!sessionRaw && this.settings && this.settings.autoCreateSession) {
                if (window.ethereum && window.ethereum.request) {
                    try {
                        const accs = await window.ethereum.request({ method: 'eth_requestAccounts' });
                        if (accs && accs.length) {
                            const addr = accs[0];
                            const sess = {
                                username: 'wallet_' + addr.substring(2, 10),
                                contractPath: localStorage.getItem('contractAddress') || this.settings.contractAddress || '/js/DigitalSignature.json',
                                address: addr
                            };
                            try { localStorage.setItem('digsig_session', JSON.stringify(sess)); } catch(e){}
                            try { localStorage.setItem('digsig_current_account', addr); } catch(e){}
                            // Reflect into in-memory settings so later steps use it
                            this.settings.currentAccount = addr;
                        }
                    } catch (e) {
                        // 授权失败或用户拒绝，忽略并继续（不跳转）
                    }
                }
            }
        } catch (e) { /* ignore */ }
        await this.loadContract();
        await this.loadAccountData();
        this.setupEventListeners();
        this.renderTxHistory();
        // 应用主题（如有）
        this.applyTheme();
    }

    async loadWeb3() {
        if (window.ethereum) {
            this.web3 = new Web3(window.ethereum);
            try {
                await window.ethereum.request({ method: 'eth_requestAccounts' });
            } catch (error) {
                console.error("用户拒绝连接钱包");
            }
        } else if (window.web3) {
            this.web3 = new Web3(window.web3.currentProvider);
        } else {
            // 如果没有钱包扩展，尝试连接到本地节点（例如 Ganache）作为回退
            try {
                const localProvider = 'http://127.0.0.1:7545';
                this.web3 = new Web3(new Web3.providers.HttpProvider(localProvider));
                console.info('未检测到 wallet，已回退到本地 provider:', localProvider);
            } catch (err) {
                alert('请安装 MetaMask 或启动本地节点 (Ganache)！');
            }
        }
    }

    async loadContract() {
        // 尝试自动加载合约 ABI 与地址，优先从可访问的构建产物读取
        let contractABI = null;
        let contractAddress = null;

        // 如果 settings.contractAddress 看起来像一个 artifact 路径或 URL，则优先尝试直接 fetch 它
        try {
            const maybePath = this.settings && this.settings.contractAddress ? this.settings.contractAddress : null;
            if (maybePath && (maybePath.endsWith('.json') || maybePath.startsWith('http') || maybePath.startsWith('/'))) {
                try {
                    const resPath = await fetch(maybePath);
                    if (resPath.ok) {
                        const jsonPath = await resPath.json();
                        contractABI = jsonPath.abi || [];
                        const networksPath = jsonPath.networks || {};
                        const preferredPath = networksPath[5777] || networksPath[1337] || Object.values(networksPath)[0];
                        if (preferredPath && preferredPath.address) contractAddress = preferredPath.address;
                        // 如果 artifact 包含 address 字段 at top-level, prefer it
                        if (!contractAddress && jsonPath.address) contractAddress = jsonPath.address;
                    }
                } catch (e) {
                    // ignore path fetch errors and continue
                }
            }
        } catch (e) {}

        // 开发时通常把 artifact 复制到 `src/js/DigitalSignature.json`，优先尝试从该路径读取（避免在 dev server 中出现 /build 的 404）
        try {
            const res2 = await fetch('/js/DigitalSignature.json');
            if (res2.ok) {
                const json2 = await res2.json();
                contractABI = json2.abi || [];
                const networks2 = json2.networks || {};
                const preferred2 = networks2[5777] || networks2[1337] || Object.values(networks2)[0];
                if (preferred2 && preferred2.address) contractAddress = preferred2.address;
            }
        } catch (e) {
            // 开发环境中如果此路径不可用则忽略，继续尝试从 build 目录读取
        }

        // 回退：尝试从 /build/contracts 读取（用于在运行 truffle build/migrate 并直接暴露 build 时）
        if (!contractABI || contractABI.length === 0) {
            try {
                const res = await fetch('/build/contracts/DigitalSignature.json');
                if (res.ok) {
                    const json = await res.json();
                    contractABI = json.abi || [];
                    const networks = json.networks || {};
                    const preferred = networks[5777] || networks[1337] || Object.values(networks)[0];
                    if (preferred && preferred.address) contractAddress = preferred.address;
                }
            } catch (e) {
                // 安静失败
            }
        }

        // 再回退：从 localStorage 获取先前保存的地址
        if (!contractAddress) {
            contractAddress = localStorage.getItem('contractAddress') || null;
        }

        // 最后提示用户输入地址（如果仍然没有）
        if (!contractAddress) {
            // 如果 settings.contractAddress 已经被 session 的 contractPath 填充，尝试使用它
            contractAddress = this.settings.contractAddress || null;
        }
        if (!contractAddress) {
            contractAddress = prompt('请输入已部署的合约地址或 artifact 路径 (例如 /js/DigitalSignature.json 或 0x...), 或取消以在本地仅查看 UI:');
            if (contractAddress) {
                localStorage.setItem('contractAddress', contractAddress);
            } else {
                // 未提供地址，避免后续调用抛错 — 将 contract 设为 null 并返回
                this.contract = null;
                return;
            }
        }

        // 保底：ABI 可能未找到，但仍创建 contract（方法调用会失败），请尽量提供 ABI
        if (!contractABI) contractABI = [];

        // 在创建 contract 之前，验证地址是否为已部署的合约（避免把 data 发送到普通账户）
        try {
            const code = await this.web3.eth.getCode(contractAddress);
            if (!code || code === '0x' || code === '0x0') {
                console.warn('loadContract: 指定地址不是合约（没有合约字节码）:', contractAddress);
                this.showAlert('合约地址无效或未部署合约：请确保已运行 `truffle migrate` 并使用部署后的合约地址。', 'warning', 8000);
                // 不创建 contract，以避免把交易发送到普通账户
                this.contract = null;
                return;
            }
        } catch (err) {
            console.warn('检查合约地址代码失败:', err);
        }

        this.contract = new this.web3.eth.Contract(contractABI, contractAddress);
    }

    async loadAccountData() {
        this.accounts = await this.web3.eth.getAccounts();
        // 如果 settings 中已保存了 currentAccount（来自登录页或本地会话），优先使用它
        if (this.settings && this.settings.currentAccount) {
            // 如果 provider 中存在该账户则使用 provider 的实例；否则仍使用保存的地址
            const wanted = this.settings.currentAccount;
            if (this.accounts && this.accounts.find(a => a.toLowerCase() === (wanted || '').toLowerCase())) {
                this.currentAccount = this.accounts.find(a => a.toLowerCase() === (wanted || '').toLowerCase());
            } else {
                this.currentAccount = wanted;
            }
        } else {
            this.currentAccount = this.accounts[0];
        }

        if (this.currentAccount) {
            document.getElementById('userAddress').textContent = 
                this.formatAddress(this.currentAccount);
            // 填充账户下拉选择器（用于切换当前账户）
            this.populateAccountSelects();
            await this.updateUserInfo();
            await this.updateDashboard();
        }
    }

    async populateAccountSelects() {
        // 填充顶部的 accountSelect 与登录模态内的 loginAccountSelect
        const sel = document.getElementById('accountSelect');
        const modalSel = document.getElementById('loginAccountSelect');

        // 尝试从 provider 实时获取账户（以支持在不同浏览器/不同钱包状态下刷新）
        try {
            if (this.web3 && this.web3.eth && typeof this.web3.eth.getAccounts === 'function') {
                const fresh = await this.web3.eth.getAccounts();
                if (fresh && fresh.length) this.accounts = fresh;
            }
        } catch (e) {
            console.warn('无法从 provider 获取账户列表:', e);
        }

        const makeOptions = (el) => {
            if (!el) return;
            el.innerHTML = '';
                // 添加默认提示项，帮助排查为何列表为空
                const placeholder = document.createElement('option');
                placeholder.value = '';
                placeholder.textContent = '请选择账户或点击刷新';
                placeholder.disabled = true;
                placeholder.selected = true;
                el.appendChild(placeholder);
                if (!this.accounts || this.accounts.length === 0) {
                    return;
                }
            for (const a of this.accounts) {
                const opt = document.createElement('option');
                opt.value = a;
                opt.textContent = this.formatAddress(a, 8, 6) + ' - ' + a;
                el.appendChild(opt);
            }
            if (this.currentAccount) el.value = this.currentAccount;
        };
        makeOptions(sel);
        makeOptions(modalSel);

        // 绑定切换事件（移除旧的再绑定）
        if (sel) {
            sel.onchange = async (e) => {
                if (!e.target.value) return;
                this.currentAccount = e.target.value;
                document.getElementById('userAddress').textContent = this.formatAddress(this.currentAccount);
                await this.updateUserInfo();
                await this.updateDashboard();
                this.showAlert('已切换账户', 'info', 1200);
            };
                // 当用户在没有账户或想刷新账户列表时，允许在按下时触发一次刷新
                sel.addEventListener('mousedown', async (evt) => {
                    try {
                        // 若支持钱包交互，触发授权请求以确保 accounts 可用
                        if (window.ethereum && window.ethereum.request) {
                            try { await window.ethereum.request({ method: 'eth_requestAccounts' }); } catch(e) { /* 用户可能拒绝 */ }
                        }
                        // 重新拉取 accounts 并重新填充选项
                        if (this.web3 && this.web3.eth && typeof this.web3.eth.getAccounts === 'function') {
                            const fresh = await this.web3.eth.getAccounts();
                            if (fresh && fresh.length) {
                                this.accounts = fresh;
                                makeOptions(sel);
                                makeOptions(modalSel);
                            }
                        }
                    } catch (e) {
                        console.warn('刷新账户列表失败:', e);
                    }
                });
        }
    }

    setupEventListeners() {
        // 连接钱包按钮
        document.getElementById('connectWallet').addEventListener('click', async () => {
            if (window.ethereum) {
                try {
                    await window.ethereum.request({ method: 'eth_requestAccounts' });
                } catch (e) {
                    console.warn('用户拒绝连接钱包');
                }
            }
            await this.loadAccountData();
        });

        // 登出按钮：清除本地会话并回到登录页
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) logoutBtn.addEventListener('click', async () => {
            try {
                await this.logout();
            } catch (e) {
                console.warn('logout error', e);
            }
        });

        // 打开设置
        const openSettingsBtn = document.getElementById('openSettings');
        if (openSettingsBtn) openSettingsBtn.addEventListener('click', () => this.showSettingsModal());

        // 打开登录/注册模态
        const openLoginBtn = document.getElementById('openLoginBtn');
        if (openLoginBtn) openLoginBtn.addEventListener('click', () => this.showLoginModal());

        // 登录模态中的保存并登录按钮
        const loginRegisterBtn = document.getElementById('loginRegisterBtn');
        if (loginRegisterBtn) loginRegisterBtn.addEventListener('click', async () => {
            const sel = document.getElementById('loginAccountSelect');
            const manual = document.getElementById('loginManualAddress');
            const nameInput = document.getElementById('loginNameInput');
            // 优先使用下拉选择的地址；如果为空则尝试使用手动输入
            let chosen = sel && sel.value ? sel.value : (manual ? manual.value.trim() : '');
            if (chosen) {
                // 如果是简短的占位值则不使用
                if (chosen.indexOf('（无可用账户）') >= 0) {
                    chosen = '';
                }
            }
            if (chosen) {
                this.currentAccount = chosen;
                document.getElementById('userAddress').textContent = this.formatAddress(this.currentAccount);
            }
            const name = nameInput ? nameInput.value.trim() : '';
            // 关闭模态
            const modal = bootstrap.Modal.getInstance(document.getElementById('loginModal'));
            if (modal) modal.hide();
            // 如果输入了名字则尝试注册
            if (name) {
                await this.registerUser(name);
            } else {
                await this.updateUserInfo();
            }
        });

        // 保存设置
        const saveSettingsBtn = document.getElementById('saveSettingsBtn');
        if (saveSettingsBtn) saveSettingsBtn.addEventListener('click', () => this.saveSettings());

        // 主题切换与刷新
        const themeBtn = document.getElementById('toggleThemeBtn');
        if (themeBtn) themeBtn.addEventListener('click', () => this.toggleTheme());

        const refreshBtn = document.getElementById('refreshDataBtn');
        if (refreshBtn) refreshBtn.addEventListener('click', async () => {
            await this.updateDashboard();
            await this.loadMyContracts();
            await this.loadPendingContracts();
            this.showAlert('已刷新数据', 'success', 1500);
        });

        // 创建合同表单
        document.getElementById('createContractForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.createContract();
        });

        // 验证合同表单
        document.getElementById('verifyContractForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.verifyContract();
        });

        // 标签切换事件
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (event) => {
                const target = event.target.getAttribute('href');
                this.onTabChange(target);
            });
        });
    }

    async onTabChange(tabId) {
        switch(tabId) {
            case '#my-contracts':
                await this.loadMyContracts();
                // 同时加载用户已签署的合同（在合约 ABI 中没有专门的接口，故通过遍历合约索引筛选）
                await this.loadSignedContracts();
                break;
            case '#pending-contracts':
                await this.loadPendingContracts();
                break;
            case '#dashboard':
                await this.updateDashboard();
                break;
        }
    }

    async updateUserInfo() {
        try {
            const user = await this.contract.methods.users(this.currentAccount).call();
            if (user.isRegistered) {
                document.getElementById('userName').textContent = user.name;
            } else {
                // 自动注册用户
                await this.registerUser();
            }
        } catch (error) {
            console.error('获取用户信息失败:', error);
        }
    }

    async registerUser() {
        // 兼容旧调用：如果传入参数则使用，否则弹出 prompt（保留兼容性）
        const args = Array.from(arguments);
        let name = args.length ? args[0] : null;
        if (!name) name = prompt('请输入您的姓名:');
        if (name) {
            // 在发送交易前，确保有可用且已授权的账户
            try {
                // 如果 provider 存在但当前账户未知或不在 provider 列表中，尝试请求授权
                if (window.ethereum && window.ethereum.request) {
                    try {
                        const provAccs = await window.ethereum.request({ method: 'eth_accounts' });
                        const hasCurrent = provAccs && provAccs.find(a => (a || '').toLowerCase() === (this.currentAccount || '').toLowerCase());
                        if (!hasCurrent) {
                            // 请求用户授权账户访问
                            try {
                                const granted = await window.ethereum.request({ method: 'eth_requestAccounts' });
                                if (granted && granted.length) {
                                    this.currentAccount = granted[0];
                                }
                            } catch (reqErr) {
                                // 用户拒绝授权或发生错误，给出友好提示并退出注册流程
                                console.warn('用户未授权钱包或授权被拒绝', reqErr);
                                this.showAlert('注册失败: 未能从钱包获取账户授权。请在钱包中允许页面访问账户，或使用本地注册。', 'warning', 8000);
                                return;
                            }
                        }
                    } catch (e) {
                        // 无法查询 eth_accounts，继续尝试 send，失败时统一处理
                    }
                }

                await this.contract.methods.registerUser(name).send({ from: this.currentAccount });
                document.getElementById('userName').textContent = name;
                this.showAlert('注册成功!', 'success');
            } catch (error) {
                console.error('registerUser on-chain error:', error);
                const msg = (error && error.message) ? error.message : String(error);
                // 常见 MetaMask 拒绝/未授权错误关键词
                if (/not been authorized|User denied|user rejected|denied signature|request was rejected/i.test(msg)) {
                    this.showAlert('注册失败: 未在钱包中授权相关操作。请在钱包中允许访问账户后重试，或使用登录页的本地注册功能。', 'warning', 8000);
                } else {
                    this.showAlert('注册失败: ' + msg, 'danger', 8000);
                }
            }
        }
    }

    // 用于独立登录页调用的登录/注册方法
    async standaloneLogin(name, address) {
        // 如果传入地址，且 web3 可用，则校验格式并设置
        if (address) {
            if (this.web3 && this.web3.utils && !this.web3.utils.isAddress(address)) {
                throw new Error('提供的地址格式不正确');
            }
            this.currentAccount = address;
        }

        // 如果未提供地址，尝试从 provider 获取第一个账户
        if (!this.currentAccount) {
            try {
                const accs = await this.web3.eth.getAccounts();
                if (accs && accs.length) this.currentAccount = accs[0];
            } catch (e) {
                console.warn('standaloneLogin 无法获取本地账户:', e);
            }
        }

        if (!this.currentAccount) {
            throw new Error('未能获取到账户，请检查钱包或手动输入地址');
        }

        try {
            // 更新 UI
            const addrEl = document.getElementById('userAddress');
            if (addrEl) addrEl.textContent = this.formatAddress(this.currentAccount);
            // 保存到 localStorage，供下一次打开使用
            try { localStorage.setItem('digsig_current_account', this.currentAccount); } catch(e) {}
            // 尝试更新用户信息并注册（如果 name 存在）
            if (name) {
                await this.registerUser(name);
            } else {
                await this.updateUserInfo();
            }
            // 重新加载合同数据
            await this.updateDashboard();
            await this.loadMyContracts();
            await this.loadPendingContracts();
        } catch (e) {
            console.error('standaloneLogin error:', e);
            throw e;
        }
    }

    // 基于本地 storage 的注册（用于离线登录界面）
    async registerLocalAccount(username, password, contractPath, address) {
        if (!username || !password) throw new Error('用户名或密码不能为空');
        const usersRaw = localStorage.getItem('digsig_users') || '{}';
        const users = JSON.parse(usersRaw || '{}');
        if (users[username]) throw new Error('用户名已存在');
        const hash = await this._hashPassword(password);
        users[username] = { passwordHash: hash, contractPath: contractPath || '', address: address || '' };
        localStorage.setItem('digsig_users', JSON.stringify(users));
        // 设置会话（包含可选 address）
        const session = { username, contractPath: contractPath || '', address: address || '' };
        localStorage.setItem('digsig_session', JSON.stringify(session));
        // 持久化当前账户（如果提供）
        if (address) {
            try { localStorage.setItem('digsig_current_account', address); } catch (e) {}
            this.settings.currentAccount = address;
            this.currentAccount = address;
        }
        // 更新内存 settings
        this.settings.currentUser = username;
        if (contractPath) this.settings.contractAddress = contractPath;
        return true;
    }

    async loginLocalAccount(username, password, address) {
        const usersRaw = localStorage.getItem('digsig_users') || '{}';
        const users = JSON.parse(usersRaw || '{}');
        const u = users[username];
        if (!u) throw new Error('用户不存在');
        const hash = await this._hashPassword(password);
        if (hash !== u.passwordHash) throw new Error('密码错误');
        // 优先使用传入的 address；否则使用用户记录中的 address
        const finalAddress = address || u.address || '';
        const session = { username, contractPath: u.contractPath || '', address: finalAddress };
        localStorage.setItem('digsig_session', JSON.stringify(session));
        // 持久化当前账户
        if (finalAddress) {
            try { localStorage.setItem('digsig_current_account', finalAddress); } catch(e) {}
            this.settings.currentAccount = finalAddress;
            this.currentAccount = finalAddress;
        }
        this.settings.currentUser = username;
        if (u.contractPath) this.settings.contractAddress = u.contractPath;
        return true;
    }

    async _hashPassword(password) {
        if (window.crypto && window.crypto.subtle) {
            const enc = new TextEncoder();
            const data = enc.encode(password);
            const digest = await crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
            // 回退到 base64（不安全，但保持功能）
            return btoa(password);
        }
    }

    async createContract() {
        // 前置检查：确保 contract 已加载且有当前账户
        if (!this.contract) {
            console.error('createContract: contract 未加载');
            this.showAlert('合约未加载：请部署合约并确保合约地址可用，或在页面中输入合约地址。', 'warning', 6000);
            return;
        }
        if (!this.currentAccount) {
            console.error('createContract: currentAccount 未设置');
            this.showAlert('未找到当前账户：请连接钱包或确保本地节点可用。', 'warning', 6000);
            return;
        }

        const title = (document.getElementById('contractTitle').value || '').trim();
        const content = (document.getElementById('contractContent').value || '').trim();
        const signerAddresses = (document.getElementById('signerAddresses').value || '')
            .split('\n')
            .map(addr => addr.trim())
            .filter(addr => addr !== '');

        // 基本输入校验，避免把交易发到链上后再 revert
        if (!this.web3) {
            this.showAlert('Web3 未初始化，无法校验输入。', 'warning');
            return;
        }
        if (!title) {
            this.showAlert('标题不能为空。', 'warning');
            return;
        }
        if (!content) {
            this.showAlert('内容不能为空。', 'warning');
            return;
        }
        if (!signerAddresses || signerAddresses.length === 0) {
            this.showAlert('请至少填写一位签约方地址（每行一个地址）。', 'warning');
            return;
        }
        for (const a of signerAddresses) {
            if (!this.web3.utils.isAddress(a)) {
                this.showAlert('签约方地址格式不正确: ' + a, 'warning', 4000);
                return;
            }
        }

        const expRaw = document.getElementById('expirationDays').value;
        const expirationDays = Number.isFinite ? parseInt(expRaw, 10) : parseInt(expRaw);
        if (Number.isNaN(expirationDays) || expirationDays < 0) {
            this.showAlert('过期天数必须为非负整数。', 'warning');
            return;
        }

        // helper: 解码 solidity revert 原因（如果返回的是标准 Error(string) ABI）
        const decodeRevertReason = (hex) => {
            try {
                if (!hex) return null;
                let h = hex;
                if (h.startsWith('0x')) h = h.slice(2);
                // selector (4 bytes) + offset (32 bytes) + length (32 bytes) = 8 + 64 + 64 = 136 hex chars
                const start = 8 + 64 + 64;
                if (h.length <= start) return null;
                const reasonHex = '0x' + h.slice(start);
                if (this.web3 && this.web3.utils && typeof this.web3.utils.hexToUtf8 === 'function') {
                    return this.web3.utils.hexToUtf8(reasonHex);
                }
                // fallback: try to decode by removing trailing zeros and converting
                const stripped = reasonHex.replace(/(00)+$/,'');
                return decodeURIComponent(escape(Buffer.from(stripped.slice(2), 'hex').toString('utf8')));
            } catch (e) {
                return null;
            }
        };

        // helper: 尝试从 RPC/MetaMask 错误中提取更友好的原因（包括 revert 原因）
        const extractRpcErrorMessage = (err) => {
            try {
                if (!err) return String(err);
                // 有时 err.data 是字符串（hex）或对象（mapping tx->data）
                const tryDecode = (maybe) => {
                    try {
                        if (!maybe) return null;
                        if (typeof maybe === 'string') {
                            const dec = decodeRevertReason(maybe);
                            if (dec) return dec;
                        }
                        if (typeof maybe === 'object') {
                            if (maybe.message) return maybe.message;
                            if (maybe.data) {
                                const d = maybe.data;
                                if (typeof d === 'string') {
                                    const dec = decodeRevertReason(d);
                                    if (dec) return dec;
                                }
                            }
                        }
                    } catch (e) {}
                    return null;
                };

                if (err.data) {
                    // err.data 可能是对象或字符串
                    const decoded = tryDecode(err.data);
                    if (decoded) return decoded;
                    // 如果是对象，遍历其值尝试解码
                    if (typeof err.data === 'object') {
                        for (const k of Object.keys(err.data || {})) {
                            const v = err.data[k];
                            const d2 = tryDecode(v);
                            if (d2) return d2;
                        }
                    }
                    if (err.data.message) return err.data.message;
                }

                if (err.error && err.error.data) {
                    const d = tryDecode(err.error.data);
                    if (d) return d;
                }

                if (err.message) return err.message;
                // 有些实现把 JSON 放在 body 或 stack
                if (err.body) {
                    try {
                        const parsed = JSON.parse(err.body);
                        if (parsed && parsed.error && parsed.error.message) return parsed.error.message;
                        if (parsed && parsed.message) return parsed.message;
                        // parsed.error.data 也可能包含 hex
                        if (parsed && parsed.error && parsed.error.data) {
                            const d = tryDecode(parsed.error.data);
                            if (d) return d;
                        }
                    } catch (e) {}
                }
                if (err.stack) return err.stack;
                return String(err);
            } catch (e) {
                return String(err);
            }
        };

        try {
            this.showLoading('创建合同中...');

            // 先尝试 estimateGas 以便在本地捕获 revert 原因并避免发送会立即失败的交易
            // 在发送交易前，确保钱包已授权当前账户（避免 MetaMask 报错未授权）
            try {
                if (window.ethereum && window.ethereum.request) {
                    try {
                        const provAccs = await window.ethereum.request({ method: 'eth_accounts' });
                        const hasCurrent = provAccs && provAccs.find(a => (a || '').toLowerCase() === (this.currentAccount || '').toLowerCase());
                        if (!hasCurrent) {
                            // 请求用户授权账户访问
                            try {
                                const granted = await window.ethereum.request({ method: 'eth_requestAccounts' });
                                if (granted && granted.length) {
                                    this.currentAccount = granted[0];
                                } else {
                                    this.hideLoading();
                                    this.showAlert('操作需要在钱包中授权账户访问。请在钱包中允许页面访问账户并重试。', 'warning', 8000);
                                    return;
                                }
                            } catch (reqErr) {
                                this.hideLoading();
                                this.showAlert('操作被钱包拒绝：未能获取账户授权。', 'warning', 8000);
                                return;
                            }
                        }
                    } catch (e) {
                        // 无法读取 eth_accounts，继续并在 send 时统一处理
                    }
                }

            } catch (e) {
                // ignore
            }

            try {
                await this.contract.methods.createContract(
                    signerAddresses,
                    title,
                    content,
                    expirationDays
                ).estimateGas({ from: this.currentAccount });
            } catch (estErr) {
                const friendlyEst = extractRpcErrorMessage(estErr);
                this.hideLoading();
                this.showAlert('无法估算 gas，交易可能会 revert：' + friendlyEst, 'danger', 8000);
                return;
            }

            const receipt = await this.contract.methods.createContract(
                signerAddresses,
                title,
                content,
                expirationDays
            ).send({
                from: this.currentAccount,
                gas: 500000
            });

            this.hideLoading();
            this.showAlert('合同创建成功!', 'success');
            document.getElementById('createContractForm').reset();
            if (receipt && receipt.transactionHash) {
                this.addTxToHistory(receipt.transactionHash, 'create', { contractTitle: title });
            }
            await this.updateDashboard();
        } catch (error) {
            this.hideLoading();
            console.error('createContract error:', error);
            const friendly = extractRpcErrorMessage(error);
            this.showAlert('创建合同失败: ' + friendly, 'danger');
        }
    }

    async signContract(contractId) {
        try {
            this.showLoading('签署合同中...');
            const receipt = await this.contract.methods.signContract(contractId).send({
                from: this.currentAccount
            });

            this.hideLoading();
            this.showAlert('合同签署成功!', 'success');
            if (receipt && receipt.transactionHash) {
                this.addTxToHistory(receipt.transactionHash, 'sign', { contractId });
            }
            await this.loadPendingContracts();
            await this.updateDashboard();
        } catch (error) {
            this.hideLoading();
            this.showAlert('签署合同失败: ' + error.message, 'danger');
        }
    }

    // 设置相关：从 localStorage 读取设置
    async loadSettings() {
        try {
            const saved = localStorage.getItem('digsig_settings');
            if (saved) {
                this.settings = JSON.parse(saved);
            }
            // ensure autoCreateSession defaults to false when not present
            if (typeof this.settings.autoCreateSession === 'undefined') this.settings.autoCreateSession = false;
            // 读取已保存的当前账户（来自独立登录页或本地会话）
            try {
                const savedAccount = localStorage.getItem('digsig_current_account');
                if (savedAccount) this.settings.currentAccount = savedAccount;
            } catch (e) {}
            try {
                const sessionRaw = localStorage.getItem('digsig_session');
                if (sessionRaw) {
                    const sess = JSON.parse(sessionRaw);
                    if (sess && sess.contractPath) {
                        // session 中的 contractPath 优先作为合约地址/路径来源
                        this.settings.contractAddress = sess.contractPath;
                    }
                    if (sess && sess.username) this.settings.currentUser = sess.username;
                    // 如果此前没有通过 digsig_current_account 读取到账户，则回退使用 session 中保存的 address
                    if (sess && sess.address && !this.settings.currentAccount) {
                        this.settings.currentAccount = sess.address;
                    }
                }
            } catch (e) {}
            // 预填充设置输入框（如果存在）
            const addrInput = document.getElementById('settingsContractAddress');
            const rpcInput = document.getElementById('settingsRpcProvider');
            const autoChk = document.getElementById('settingsAutoSession');
            if (addrInput && this.settings.contractAddress) addrInput.value = this.settings.contractAddress;
            if (rpcInput && this.settings.rpcProvider) rpcInput.value = this.settings.rpcProvider;
            if (autoChk) autoChk.checked = !!this.settings.autoCreateSession;
        } catch (e) {
            console.warn('加载设置失败', e);
        }
    }

    async saveSettings() {
        const addrInput = document.getElementById('settingsContractAddress');
        const rpcInput = document.getElementById('settingsRpcProvider');
        const autoChk = document.getElementById('settingsAutoSession');
        this.settings.contractAddress = addrInput ? addrInput.value.trim() : this.settings.contractAddress;
        this.settings.rpcProvider = rpcInput ? rpcInput.value.trim() : this.settings.rpcProvider;
        if (autoChk) this.settings.autoCreateSession = !!autoChk.checked;
        localStorage.setItem('digsig_settings', JSON.stringify(this.settings));

        // 如果合约地址已改动，重新加载合约
        if (this.settings.contractAddress) {
            localStorage.setItem('contractAddress', this.settings.contractAddress);
        }

        // 隐藏模态
        const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
        if (modal) modal.hide();

        this.showAlert('设置已保存', 'success');
        // 重新尝试加载合约（如果 web3 已存在）
        if (this.web3) await this.loadContract();
    }

    showSettingsModal() {
        const modalEl = document.getElementById('settingsModal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    }

    showLoginModal() {
        console.log('showLoginModal called; app.currentAccount=', this.currentAccount);
        // 确保账户下拉已填充
        if (!this.accounts || this.accounts.length === 0) {
            // 尝试从 web3 获取
            if (this.web3) {
                this.web3.eth.getAccounts().then(accs => {
                    this.accounts = accs || [];
                    this.populateAccountSelects();
                    const modal = new bootstrap.Modal(document.getElementById('loginModal'));
                    modal.show();
                }).catch(() => {
                    const modal = new bootstrap.Modal(document.getElementById('loginModal'));
                    modal.show();
                });
            } else {
                const modal = new bootstrap.Modal(document.getElementById('loginModal'));
                modal.show();
            }
            return;
        }
        this.populateAccountSelects();
        const modalEl = document.getElementById('loginModal');
        if (!modalEl) {
            console.warn('loginModal element not found');
            return;
        }
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    }

    addTxToHistory(txHash, type = 'tx', meta = {}) {
        const entry = { txHash, type, meta, time: Date.now() };
        this.txHistory.unshift(entry);
        // keep recent 50
        if (this.txHistory.length > 50) this.txHistory.length = 50;
        localStorage.setItem('digsig_tx_history', JSON.stringify(this.txHistory));
        this.renderTxHistory();
    }

    renderTxHistory() {
        // 尝试从 localStorage 恢复
        try {
            const saved = localStorage.getItem('digsig_tx_history');
            if (saved) this.txHistory = JSON.parse(saved);
        } catch (e) {}

        const container = document.getElementById('txHistory');
        if (!container) return;
        if (this.txHistory.length === 0) {
            container.innerHTML = '<p class="text-muted">暂无交易记录。</p>';
            return;
        }

        container.innerHTML = this.txHistory.map(tx => `
            <div class="card mb-2">
                <div class="card-body small">
                    <div><strong>${tx.type.toUpperCase()}</strong> — ${new Date(tx.time).toLocaleString()}</div>
                    <div>Tx: <a href="#" title="${tx.txHash}">${this.formatAddress(tx.txHash,10,6)}</a></div>
                </div>
            </div>
        `).join('');
    }

    // 主题切换
    toggleTheme() {
        const current = localStorage.getItem('digsig_theme') || 'light';
        const next = current === 'light' ? 'dark' : 'light';
        localStorage.setItem('digsig_theme', next);
        this.applyTheme();
        this.showAlert('已切换到 ' + next + ' 主题', 'info', 1500);
    }

    applyTheme() {
        const theme = localStorage.getItem('digsig_theme') || 'light';
        if (theme === 'dark') {
            document.body.classList.add('theme-dark');
        } else {
            document.body.classList.remove('theme-dark');
        }
    }

    // 导出合同详情为 JSON 文件
    exportContract(contract) {
        try {
            const payload = {
                id: contract.id,
                title: contract.title,
                content: contract.content,
                signers: contract.signers,
                isSigned: contract.isSigned,
                creator: contract.creator,
                createdAt: contract.createdAt,
                expiresAt: contract.expiresAt,
                contentHash: contract.contentHash
            };
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `contract-${contract.id}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            this.showAlert('已导出合同 JSON', 'success', 2000);
        } catch (e) {
            this.showAlert('导出失败: ' + e.message, 'danger');
        }
    }

    async loadMyContracts() {
        try {
            const contractIds = await this.contract.methods.getUserCreatedContracts(this.currentAccount).call();
            const container = document.getElementById('myContractsList');
            container.innerHTML = '';

            if (contractIds.length === 0) {
                container.innerHTML = '<p class="text-muted">暂无创建的合同</p>';
                return;
            }

            for (const contractId of contractIds) {
                const contract = await this.contract.methods.getContract(contractId).call();
                const card = this.createContractCard(contract, false);
                container.appendChild(card);
            }
        } catch (error) {
            console.error('加载我的合同失败:', error);
        }
    }

    async loadPendingContracts() {
        try {
            const contractIds = await this.contract.methods.getUserPendingContracts(this.currentAccount).call();
            const container = document.getElementById('pendingContractsList');
            container.innerHTML = '';

            if (contractIds.length === 0) {
                container.innerHTML = '<p class="text-muted">暂无待签署合同</p>';
                return;
            }

            for (const contractId of contractIds) {
                const contract = await this.contract.methods.getContract(contractId).call();
                const card = this.createContractCard(contract, true);
                container.appendChild(card);
            }
        } catch (error) {
            console.error('加载待签署合同失败:', error);
        }
    }

    // 加载当前账户已签署的合同并渲染到 #signedContractsList
    async loadSignedContracts() {
        try {
            if (!this.contract) return;
            const container = document.getElementById('signedContractsList');
            if (!container) return;
            container.innerHTML = '';

            // 获取合约总数（注意：若数量很大，此遍历可能较慢）
            const total = await this.contract.methods.contractCount().call();
            const totalNum = parseInt(total || 0, 10);
            if (totalNum === 0) {
                container.innerHTML = '<p class="text-muted">暂无已签署合同</p>';
                return;
            }

            let found = false;
            // 遍历每个合约并检查当前账户是否为签约方且已签署
            for (let i = 1; i <= totalNum; i++) {
                try {
                    const c = await this.contract.methods.getContract(i).call();
                    if (!c || !c.signers) continue;
                    const signers = c.signers.map(s => (s || '').toLowerCase());
                    const idx = signers.indexOf((this.currentAccount || '').toLowerCase());
                    if (idx >= 0) {
                        // 有 isSigned 数组时检查对应位置
                        if (Array.isArray(c.isSigned) && c.isSigned[idx]) {
                            found = true;
                            const card = this.createContractCard(c, false);
                            container.appendChild(card);
                        } else if (c.isCompleted) {
                            // 若没有单独的 isSigned 标记但合约标为完成，也视为已签署
                            found = true;
                            const card = this.createContractCard(c, false);
                            container.appendChild(card);
                        }
                    }
                } catch (err) {
                    // 单个合约读取失败时记录并继续
                    console.warn('读取合约 #' + i + ' 失败:', err);
                }
            }

            if (!found) {
                container.innerHTML = '<p class="text-muted">暂无已签署合同</p>';
            }
        } catch (error) {
            console.error('加载已签署合同失败:', error);
        }
    }

    createContractCard(contract, showSignButton = false) {
        const card = document.createElement('div');
        card.className = 'card contract-card mb-3';
        
        const status = contract.isCompleted ? 'completed' : 
                      (new Date(contract.expiresAt * 1000) < new Date() ? 'expired' : 'pending');
        
        const statusText = {
            'completed': '已完成',
            'expired': '已过期',
            'pending': '进行中'
        }[status];

        const statusClass = {
            'completed': 'bg-success',
            'expired': 'bg-danger',
            'pending': 'bg-warning'
        }[status];

        card.innerHTML = `
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h5 class="card-title">${contract.title}</h5>
                        <p class="card-text text-muted">合同ID: ${contract.id}</p>
                        <p class="card-text">${contract.content.substring(0, 100)}...</p>
                    </div>
                    <span class="badge ${statusClass} status-badge">${statusText}</span>
                </div>
                <div class="mt-3">
                    <small class="text-muted">
                        创建时间: ${new Date(contract.createdAt * 1000).toLocaleString()} | 
                        到期时间: ${new Date(contract.expiresAt * 1000).toLocaleString()}
                    </small>
                </div>
                <div class="mt-2">
                    <button class="btn btn-outline-primary btn-sm me-2 view-details-btn" data-contract-id="${contract.id}">
                        查看详情
                    </button>
                    ${showSignButton ? 
                        `<button class="btn btn-primary btn-sm sign-contract-btn" data-contract-id="${contract.id}">
                            签署合同
                        </button>` : ''
                    }
                </div>
            </div>
        `;
        // 绑定事件处理器（避免使用内联 onclick，兼容 CSP 且更稳健）
        const viewBtn = card.querySelector('.view-details-btn');
        if (viewBtn) {
            viewBtn.addEventListener('click', (e) => {
                const id = e.currentTarget.getAttribute('data-contract-id');
                this.showContractDetails(id);
            });
        }
        const signBtn = card.querySelector('.sign-contract-btn');
        if (signBtn) {
            signBtn.addEventListener('click', (e) => {
                const id = e.currentTarget.getAttribute('data-contract-id');
                this.signContract(id);
            });
        }

        return card;
    }

async showContractDetails(contractId) {
        try {
            const contract = await this.contract.methods.getContract(contractId).call();

            // Ensure modal exists in DOM (some builds or edits may remove it). Create a fallback modal if missing.
            this._ensureContractModalExists();

            const modalTitle = document.getElementById('contractModalTitle');
            const modalBody = document.getElementById('contractModalBody');
            if (!modalTitle || !modalBody) {
                throw new Error('合同详情模态框元素未找到');
            }

            modalTitle.textContent = contract.title || ('合同 #' + contractId);
            
            const signersList = contract.signers.map((signer, index) => `
                <div class="signer-item">
                    <div>
                        <strong>${this.formatAddress(signer)}</strong>
                        <span class="badge ${contract.isSigned[index] ? 'bg-success' : 'bg-secondary'} ms-2">
                            ${contract.isSigned[index] ? '已签署' : '待签署'}
                        </span>
                    </div>
                    ${signer.toLowerCase() === this.currentAccount.toLowerCase() ? 
                        '<span class="badge bg-primary">我</span>' : ''}
                </div>
            `).join('');
            
            modalBody.innerHTML = `
                <div class="contract-details">
                    <h6>合同内容:</h6>
                    <p>${this.escapeHtml(contract.content)}</p>
                    
                    <h6 class="mt-3">签约方:</h6>
                    <div class="signer-list">
                        ${signersList}
                    </div>
                    
                    <h6 class="mt-3">合同信息:</h6>
                    <ul class="list-unstyled">
                        <li><strong>合同ID:</strong> ${contract.id}</li>
                        <li><strong>创建者:</strong> ${this.formatAddress(contract.creator)}</li>
                        <li><strong>创建时间:</strong> ${this.formatTimestamp(contract.createdAt)}</li>
                        <li><strong>到期时间:</strong> ${this.formatTimestamp(contract.expiresAt)}</li>
                        <li><strong>状态:</strong> ${contract.isCompleted ? '已完成' : '进行中'}</li>
                        <li><strong>内容哈希:</strong> <code>${contract.contentHash}</code></li>
                    </ul>
                </div>
            `;

            // 添加导出按钮（每次更新，确保事件处理器引用当前 contract）
            let footer = document.querySelector('#contractModal .modal-footer');
            if (!footer) {
                // create footer if missing
                const modalContent = document.querySelector('#contractModal .modal-content');
                if (modalContent) {
                    footer = document.createElement('div');
                    footer.className = 'modal-footer';
                    modalContent.appendChild(footer);
                }
            }
            if (footer) {
                const existing = document.getElementById('exportContractBtn');
                if (existing) existing.remove();
                const btn = document.createElement('button');
                btn.className = 'btn btn-outline-primary';
                btn.id = 'exportContractBtn';
                btn.textContent = '导出合同';
                btn.addEventListener('click', () => this.exportContract(contract));
                footer.insertBefore(btn, footer.firstChild);
            }
            
            // 显示模态框
            const modal = new bootstrap.Modal(document.getElementById('contractModal'));
            modal.show();
            
        } catch (error) {
            console.error('showContractDetails error:', error);
            this.showAlert('加载合同详情失败: ' + (error && error.message ? error.message : error), 'danger');
        }
    }

    _ensureContractModalExists() {
        const existing = document.getElementById('contractModal');
        // If existing modal is present but missing key children, remove and recreate it
        if (existing) {
            const hasTitle = !!existing.querySelector('#contractModalTitle');
            const hasBody = !!existing.querySelector('#contractModalBody');
            if (hasTitle && hasBody) return; // good
            try { existing.remove(); } catch (e) { /* ignore */ }
        }

        // build a minimal modal structure matching expected IDs
        const modalHtml = `
            <div class="modal fade" id="contractModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="contractModalTitle">合同详情</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body" id="contractModalBody"></div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                        </div>
                    </div>
                </div>
            </div>`;
        const wrapper = document.createElement('div');
        wrapper.innerHTML = modalHtml;
        document.body.appendChild(wrapper.firstElementChild);
    }

    async verifyContract() {
        const contractId = document.getElementById('verifyContractId').value;
        const content = document.getElementById('verifyContent').value;
        
        if (!contractId || !content.trim()) {
            this.showAlert('请输入合同ID和内容', 'warning');
            return;
        }

        try {
            this.showLoading('验证合同中...');
            
            const isValid = await this.contract.methods.verifyContract(contractId, content).call();
            
            this.hideLoading();
            
            const resultDiv = document.getElementById('verificationResult');
            if (isValid) {
                resultDiv.innerHTML = `
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i>
                        合同验证成功！该合同内容与区块链记录一致。
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        合同验证失败！该合同内容与区块链记录不一致。
                    </div>
                `;
            }
            
        } catch (error) {
            this.hideLoading();
            this.showAlert('验证合同失败: ' + error.message, 'danger');
        }
    }

    async updateDashboard() {
        if (!this.contract || !this.currentAccount) return;

        try {
            const createdContracts = await this.contract.methods.getUserCreatedContracts(this.currentAccount).call();
            const pendingContracts = await this.contract.methods.getUserPendingContracts(this.currentAccount).call();
            const totalContracts = await this.contract.methods.contractCount().call();
            
            const statsContainer = document.getElementById('dashboardStats');
            statsContainer.innerHTML = `
                <div class="col-md-4">
                    <div class="card text-white bg-primary mb-3">
                        <div class="card-body">
                            <h5 class="card-title">${createdContracts.length}</h5>
                            <p class="card-text">我创建的合同</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-warning mb-3">
                        <div class="card-body">
                            <h5 class="card-title">${pendingContracts.length}</h5>
                            <p class="card-text">待签署合同</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-success mb-3">
                        <div class="card-body">
                            <h5 class="card-title">${totalContracts}</h5>
                            <p class="card-text">平台总合同数</p>
                        </div>
                    </div>
                </div>
            `;
            
        } catch (error) {
            console.error('更新仪表板失败:', error);
        }
    }

    // 工具方法
    formatAddress(address, startLength = 6, endLength = 4) {
        if (!address) return '';
        return `${address.substring(0, startLength)}...${address.substring(address.length - endLength)}`;
    }

    formatTimestamp(timestamp) {
        return new Date(timestamp * 1000).toLocaleString('zh-CN');
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    showLoading(message = '处理中...') {
        // 创建或显示加载动画
        let spinner = document.getElementById('loadingSpinner');
        if (!spinner) {
            spinner = document.createElement('div');
            spinner.id = 'loadingSpinner';
            spinner.className = 'loading-spinner';
            spinner.innerHTML = `
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">加载中...</span>
                </div>
                <div class="mt-2">${message}</div>
            `;
            document.body.appendChild(spinner);
        }
        spinner.style.display = 'block';
    }

    hideLoading() {
        const spinner = document.getElementById('loadingSpinner');
        if (spinner) {
            spinner.style.display = 'none';
        }
    }

    showAlert(message, type = 'info', duration = 3000) {
        // 创建警告容器（如果不存在）
        let alertContainer = document.getElementById('alertContainer');
        if (!alertContainer) {
            alertContainer = document.createElement('div');
            alertContainer.id = 'alertContainer';
            alertContainer.className = 'alert-container';
            document.body.appendChild(alertContainer);
        }

        const alertId = 'alert-' + Date.now();
        const alert = document.createElement('div');
        alert.id = alertId;
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        alertContainer.appendChild(alert);

        // 自动消失
        if (duration > 0) {
            setTimeout(() => {
                this.removeAlert(alertId);
            }, duration);
        }

        return alertId;
    }

    removeAlert(alertId) {
        const alert = document.getElementById(alertId);
        if (alert) {
            alert.remove();
        }
    }

    // 登出：清除会话相关的本地存储并跳转到登录页
    async logout() {
        try {
            // 清理会话与当前账户
            try { localStorage.removeItem('digsig_session'); } catch(e) {}
            try { localStorage.removeItem('digsig_current_account'); } catch(e) {}
            // 保留用户设置（如 autoCreateSession / contractAddress），但清空登录用户记录
            this.currentAccount = null;
            if (this.settings) this.settings.currentUser = null;
            // 清理 UI
            const addrEl = document.getElementById('userAddress'); if (addrEl) addrEl.textContent = '';
            const nameEl = document.getElementById('userName'); if (nameEl) nameEl.textContent = '';
        } catch (e) {
            console.warn('logout cleanup failed', e);
        }
        // 跳转到登录页面
        try {
            location.href = '/login.html';
        } catch (e) {
            console.warn('redirect to login failed', e);
        }
    }
}

// 全局应用实例
let app;

// 页面加载完成后初始化应用
window.addEventListener('load', function() {
    try {
        // 如果已有全局实例（fallback 已初始化），则不要重复创建
        if (!window.app) {
            window.app = new DigitalSignatureApp();
            // 兼容旧代码：确保全局变量 `app` 可直接使用（例如内联 onclick 引用）
            try { app = window.app; } catch(e) { window.app = window.app; }
        } else {
            console.info('DigitalSignatureApp already initialized; skipping load-time init');
        }
    } catch (e) {
        window.__digsig_init_error = (e && e.stack) ? e.stack : String(e);
        console.error('DigitalSignatureApp init error:', e);
    }
});

// 导出到全局作用域
window.DigitalSignatureApp = DigitalSignatureApp;

// Fallback: 若尚未初始化（某些浏览器或扩展阻止 load 事件），尝试尽快初始化
try {
    if (!window.app && typeof DigitalSignatureApp === 'function') {
        try {
            window.app = new DigitalSignatureApp();
            try { app = window.app; } catch(e) { /* ignore */ }
            console.info('DigitalSignatureApp fallback init executed');
        } catch (e) {
            window.__digsig_init_error = (e && e.stack) ? e.stack : String(e);
            console.warn('Fallback init failed', e);
        }
    }
} catch (e) {
    window.__digsig_init_error = (e && e.stack) ? e.stack : String(e);
    console.warn('Fallback outer error', e);
}