/**
 * 多语言项目迁移系统 - 前端 JavaScript
 */

// ==================== 全局变量 ====================
let currentSessionId = null;
let currentMigrationId = null;
let currentReport = null;
let currentMigrationTaskId = null;
let charts = {};
let selectedFiles = []; // 全局存储选中的文件及其路径信息

// ==================== 初始化 ====================
const API_BASE_URL = (window.API_CONFIG?.BASE_URL || '').replace(/\/+$/, '');

function buildApiUrl(path) {
    if (!path.startsWith('/')) {
        path = `/${path}`;
    }
    return API_BASE_URL ? `${API_BASE_URL}${path}` : path;
}

document.addEventListener('DOMContentLoaded', function () {
    initializeEventListeners();
    loadLanguages();
    
    // 🔥 添加窗口大小改变时图表自适应
    window.addEventListener('resize', function() {
        Object.keys(charts).forEach(key => {
            if (charts[key] && typeof charts[key].resize === 'function') {
                charts[key].resize();
            }
        });
    });
});

/**
 * 递归读取目录（Chrome 单次 readEntries 有数量上限，需循环）
 */
function readAllDirectoryEntries(reader) {
    return new Promise((resolve) => {
        const acc = [];
        const readBatch = () => {
            reader.readEntries(
                (entries) => {
                    if (!entries.length) {
                        resolve(acc);
                        return;
                    }
                    acc.push(...entries);
                    readBatch();
                },
                () => resolve(acc)
            );
        };
        readBatch();
    });
}

/**
 * 遍历 FileSystemEntry，产出带 webkitRelativePath 的 File 列表（用于拖拽文件夹）
 */
async function traverseFileTree(entry, pathPrefix, out) {
    if (entry.isFile) {
        await new Promise((resolve) => {
            entry.file(
                (file) => {
                    const rel = pathPrefix + file.name;
                    try {
                        Object.defineProperty(file, 'webkitRelativePath', {
                            value: rel,
                            configurable: true,
                            enumerable: true,
                        });
                    } catch (_) { /* 部分浏览器只读，忽略 */ }
                    out.push(file);
                    resolve();
                },
                () => resolve()
            );
        });
    } else if (entry.isDirectory) {
        const dirPath = pathPrefix + entry.name + '/';
        const reader = entry.createReader();
        const children = await readAllDirectoryEntries(reader);
        for (const child of children) {
            await traverseFileTree(child, dirPath, out);
        }
    }
}

/**
 * 从 DataTransfer 收集文件（解决拖拽文件夹时 files 为空或不完整的问题）
 */
async function getFilesFromDataTransfer(dataTransfer) {
    const items = dataTransfer.items;
    if (items && items.length > 0) {
        const collected = [];
        const tasks = [];
        for (let i = 0; i < items.length; i++) {
            const item = items[i];
            if (item.kind !== 'file') continue;
            if (item.webkitGetAsEntry) {
                const entry = item.webkitGetAsEntry();
                if (entry) {
                    tasks.push(traverseFileTree(entry, '', collected));
                }
            } else {
                const f = item.getAsFile();
                if (f) collected.push(f);
            }
        }
        await Promise.all(tasks);
        if (collected.length > 0) {
            return collected;
        }
    }
    return Array.from(dataTransfer.files || []);
}

function initializeEventListeners() {
    const uploadDropZone = document.getElementById('uploadDropZone');
    const fileInput = document.getElementById('fileInput');
    const singleFileInput = document.getElementById('singleFileInput');
    const pickFilesBtn = document.getElementById('pickFilesBtn');
    const pickFolderBtn = document.getElementById('pickFolderBtn');

    pickFilesBtn.addEventListener('click', () => singleFileInput.click());
    pickFolderBtn.addEventListener('click', () => fileInput.click());

    ['dragenter', 'dragover'].forEach((evt) => {
        uploadDropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            uploadDropZone.classList.add('drag-over');
        });
    });

    uploadDropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!uploadDropZone.contains(e.relatedTarget)) {
            uploadDropZone.classList.remove('drag-over');
        }
    });

    uploadDropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        uploadDropZone.classList.remove('drag-over');
        const rawFiles = await getFilesFromDataTransfer(e.dataTransfer);
        handleFileSelect(rawFiles);
    });

    // 文件夹上传
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files);
        }
        e.target.value = '';
    });

    // 单个/多个文件上传
    singleFileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files);
        }
        e.target.value = '';
    });

    // 按钮事件
    document.getElementById('uploadBtn').addEventListener('click', uploadFiles);
    document.getElementById('migrateBtn').addEventListener('click', startMigration);
    document.getElementById('downloadBtn').addEventListener('click', downloadProject);
    document.getElementById('downloadReportBtn').addEventListener('click', downloadReport);

    // 漏洞标签切换
    const beforeVulnsBtn = document.getElementById('before-vulns-btn');
    const afterVulnsBtn = document.getElementById('after-vulns-btn');
    beforeVulnsBtn.addEventListener('click', () => {
        document.getElementById('beforeVulns').style.display = 'block';
        document.getElementById('afterVulns').style.display = 'none';
        beforeVulnsBtn.classList.add('active');
        afterVulnsBtn.classList.remove('active');
    });
    afterVulnsBtn.addEventListener('click', () => {
        document.getElementById('beforeVulns').style.display = 'none';
        document.getElementById('afterVulns').style.display = 'block';
        afterVulnsBtn.classList.add('active');
        beforeVulnsBtn.classList.remove('active');
    });

    // GitHub 导入事件
    document.getElementById('validateGithubBtn').addEventListener('click', validateAndImportGitHub);
}

/**
 * 校验 GitHub 地址并从服务端拉取仓库（ZIP），成功后与本地上传共用同一套迁移流程
 */
async function validateAndImportGitHub() {
    const urlInput = document.getElementById('githubUrlInput');
    const branchInput = document.getElementById('githubBranchInput');
    const rawUrl = (urlInput.value || '').trim();
    const branchTyped = (branchInput.value || '').trim();

    if (!rawUrl) {
        showAlert('提示', '请输入 GitHub 仓库链接', 'warning');
        return;
    }

    const githubLoading = document.getElementById('githubLoading');
    const githubStatus = document.getElementById('githubStatus');
    const validateBtn = document.getElementById('validateGithubBtn');

    githubLoading.style.display = 'block';
    githubStatus.style.display = 'none';
    validateBtn.disabled = true;

    try {
        const valRes = await axios.post(buildApiUrl('/api/github/validate'), { url: rawUrl });
        const val = valRes.data;

        if (!val.success) {
            throw new Error(val.error || '验证请求失败');
        }
        if (!val.valid) {
            showGithubStatus(false, val.error || '无效的仓库地址');
            showAlert('错误', val.error || '无效的仓库地址', 'danger');
            return;
        }

        const payload = { url: val.normalized_url || rawUrl };
        if (branchTyped) {
            payload.branch = branchTyped;
        }

        showLog('info', '[GitHub] 正在下载仓库归档并解析源代码文件…');
        const impRes = await axios.post(buildApiUrl('/api/github/import'), payload, {
            timeout: 180000,
            headers: { 'Content-Type': 'application/json' }
        });
        const data = impRes.data;

        if (!data.success) {
            showGithubStatus(false, data.error || '导入失败');
            showAlert('错误', data.error || '导入失败', 'danger');
            showLog('error', `[GitHub] ${data.error || '导入失败'}`);
            return;
        }

        currentSessionId = data.session_id;
        selectedFiles = [];
        document.getElementById('filesList').style.display = 'none';
        document.getElementById('uploadBtn').disabled = true;

        document.getElementById('projectInfo').style.display = 'block';
        document.getElementById('fileCount').textContent = data.files_count ?? 0;
        const langs = data.languages || [];
        document.getElementById('detectedLangs').textContent = langs.length ? langs.join(', ') : '-';
        document.getElementById('totalSize').textContent = formatFileSize(data.total_size || 0);

        const srcSelect = document.getElementById('srcLang');
        if (langs.length === 1) {
            srcSelect.value = langs[0];
        }

        document.getElementById('migrateBtn').disabled = false;

        const fullName = data.repo_info?.full_name || '';
        const br = data.branch || '';
        const hint = fullName
            ? `已导入 ${fullName}${br ? `（${br}）` : ''}，共 ${data.files_count} 个可迁移文件`
            : `导入完成，共 ${data.files_count} 个可迁移文件`;
        showGithubStatus(true, hint);
        showAlert('成功', `已从 GitHub 拉取 ${data.files_count} 个源代码文件`, 'success');
        showLog('success', `[GitHub] ${hint}`);
    } catch (error) {
        const msg = error.response?.data?.error || error.message || '导入失败';
        showGithubStatus(false, msg);
        handleError('GitHub 导入失败', error);
    } finally {
        githubLoading.style.display = 'none';
        validateBtn.disabled = false;
    }
}

function showGithubStatus(success, message) {
    const githubStatus = document.getElementById('githubStatus');
    const githubStatusAlert = document.getElementById('githubStatusAlert');
    const githubStatusContent = document.getElementById('githubStatusContent');
    if (!githubStatus || !githubStatusAlert || !githubStatusContent) return;
    githubStatus.style.display = 'block';
    githubStatusAlert.className = 'alert ' + (success ? 'alert-success' : 'alert-danger');
    githubStatusContent.textContent = message;
}

// ==================== 文件处理 ====================
// let selectedFiles = []; // 全局存储选中的文件及其路径信息  // 移除重复声明

function handleFileSelect(files) {
    console.log('[DEBUG] handleFileSelect 被调用');
    const list = Array.isArray(files) ? files : Array.from(files || []);
    console.log('[DEBUG] 文件数量:', list.length);

    if (list.length === 0) {
        console.warn('[WARN] 没有文件');
        return;
    }

    const allowedExts = ['.py', '.java', '.cpp', '.c', '.js', '.go', '.h'];
    
    // 过滤有效文件并保存路径信息
    selectedFiles = list.filter(file => {
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        const isValid = allowedExts.includes(ext);
        if (!isValid) {
            console.log(`[INFO] 跳过不支持的文件: ${file.name} (${ext})`);
        }
        return isValid;
    }).map(file => ({
        file: file,
        path: (file.webkitRelativePath || file.name).replace(/\\/g, '/'),
        name: file.name,
        size: file.size
    }));

    console.log('[DEBUG] 有效文件数量:', selectedFiles.length);
    console.log('[DEBUG] 文件列表:', selectedFiles.map(f => f.path));

    if (selectedFiles.length === 0) {
        showAlert('错误', '没有有效的代码文件！支持: .py, .java, .cpp, .c, .js, .go', 'danger');
        showLog('warning', '[WARN] 没有有效的代码文件');
        return;
    }

    // 显示文件列表（包含文件夹结构）
    showFilesList(selectedFiles);

    // 启用上传按钮
    document.getElementById('uploadBtn').disabled = false;
    showLog('success', `[OK] 已选择 ${selectedFiles.length} 个文件，可以上传了`);
}

function showFilesList(files) {
    const filesList = document.getElementById('filesList');
    const filesListItems = document.getElementById('filesListItems');
    
    filesList.style.display = 'block';
    filesListItems.innerHTML = '';

    // 识别文件夹结构
    let folderCount = 0;
    let rootFolder = '';
    
    // 尝试识别根文件夹
    const filePaths = files.map(f => f.path);
    if (filePaths.length > 0 && filePaths[0].includes('/')) {
        rootFolder = filePaths[0].split('/')[0];
        if (rootFolder) {
            folderCount = 1;
            filesListItems.innerHTML += `<li class="list-group-item bg-info text-white"><i class="bi bi-folder"></i> <strong>${rootFolder}/</strong> (文件夹)</li>`;
        }
    }

    files.forEach((fileInfo, index) => {
        const li = document.createElement('li');
        li.className = 'list-group-item text-sm';
        
        // 显示文件的相对路径（包含文件夹）
        const pathBits = fileInfo.path.split('/');
        const relativePath = pathBits.slice(folderCount > 0 ? 1 : 0).join('/');
        
        // 计算缩进级别
        const depth = fileInfo.path.split('/').length - 1;
        const indent = '&nbsp;'.repeat(Math.max(0, depth - 1) * 4);
        
        li.innerHTML = `
            <span>
                ${indent}<i class="bi bi-file-earmark-code"></i>
                ${relativePath}
                <small class="text-muted">(${formatFileSize(fileInfo.size)})</small>
            </span>
            <span class="file-remove" onclick="removeFile(${index})" title="移除">×</span>
        `;
        filesListItems.appendChild(li);
    });
    
    // 显示统计摘要
    const summary = document.createElement('li');
    summary.className = 'list-group-item bg-light';
    summary.innerHTML = `<strong>[*] 共 ${files.length} 个文件${folderCount > 0 ? ' (来自 1 个文件夹)' : ''}</strong>`;
    filesListItems.appendChild(summary);
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    
    if (selectedFiles.length === 0) {
        document.getElementById('filesList').style.display = 'none';
        document.getElementById('uploadBtn').disabled = true;
    } else {
        showFilesList(selectedFiles);
    }
}

// ==================== 上传 ====================
async function uploadFiles() {
    console.log('[DEBUG] uploadFiles 被调用');
    console.log('[DEBUG] selectedFiles 数量:', selectedFiles.length);
    
    if (selectedFiles.length === 0) {
        showAlert('错误', '请先选择文件', 'danger');
        showLog('warning', '[WARN] 没有选择文件');
        return;
    }

    const formData = new FormData();
    
    // 添加文件和路径信息
    selectedFiles.forEach((fileInfo, index) => {
        formData.append('files', fileInfo.file);
        formData.append(`path_${index}`, fileInfo.path);
        console.log(`[DEBUG] 添加文件 ${index}: ${fileInfo.path}`);
    });

    // 禁用按钮
    document.getElementById('uploadBtn').disabled = true;
    document.getElementById('migrateBtn').disabled = true;

    const progressEl = document.getElementById('progressContainer');
    progressEl.style.display = 'block';
    setProgressIndeterminate(false);
    updateProgress(0, '准备上传…');

    let uploadOk = false;

    try {
        showLog('info', '[*] 上传文件中...');
        console.log('[DEBUG] 开始发送请求到 /api/upload');
        
        const response = await axios.post(buildApiUrl('/api/upload'), formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
            onUploadProgress: (ev) => {
                if (ev.total) {
                    const pct = Math.min(100, Math.round((ev.loaded * 100) / ev.total));
                    updateProgress(
                        pct,
                        `上传中 ${pct}%（${formatFileSize(ev.loaded)} / ${formatFileSize(ev.total)}）`
                    );
                } else {
                    setProgressIndeterminate(true, `已发送 ${formatFileSize(ev.loaded)}…`);
                }
            },
        });

        console.log('[DEBUG] 收到响应:', response.data);
        
        const data = response.data;
        if (data.success) {
            uploadOk = true;
            setProgressIndeterminate(false);
            updateProgress(100, '上传完成，正在解析响应…');
            currentSessionId = data.session_id;

            // 显示项目信息
            document.getElementById('projectInfo').style.display = 'block';
            document.getElementById('fileCount').textContent = data.files_count || selectedFiles.length;
            document.getElementById('detectedLangs').textContent = data.languages.join(', ') || '-';
            document.getElementById('totalSize').textContent = formatFileSize(data.total_size);

            // 自动填充源语言
            if (data.languages.length === 1) {
                document.getElementById('srcLang').value = data.languages[0];
            }

            // 启用迁移按钮
            document.getElementById('migrateBtn').disabled = false;

            showAlert('成功', `[OK] 上传成功！检测到 ${selectedFiles.length} 个文件`, 'success');
            showLog('success', `[OK] 上传成功！检测到 ${selectedFiles.length} 个文件`);

            setTimeout(() => {
                progressEl.style.display = 'none';
                updateProgress(0, '');
            }, 900);
        } else {
            showAlert('错误', data.error, 'danger');
            showLog('error', `[ERROR] 上传失败: ${data.error}`);
        }
    } catch (error) {
        console.error('[ERROR] 上传异常:', error);
        handleError('上传失败', error);
    } finally {
        document.getElementById('uploadBtn').disabled = false;
        if (!uploadOk) {
            setProgressIndeterminate(false);
            progressEl.style.display = 'none';
            updateProgress(0, '');
        }
    }
}

// ==================== 迁移 ====================
async function startMigration() {
    const srcLang = document.getElementById('srcLang').value;
    const tgtLang = document.getElementById('tgtLang').value;

    if (!currentSessionId) {
        showAlert('错误', '请先本地上传项目或从 GitHub 导入仓库', 'danger');
        return;
    }

    if (!srcLang || !tgtLang) {
        showAlert('错误', '请选择源语言和目标语言', 'danger');
        return;
    }

    if (srcLang === tgtLang) {
        showAlert('错误', '源语言和目标语言不能相同', 'danger');
        return;
    }

    // 禁用按钮和选择框
    document.getElementById('migrateBtn').disabled = true;
    document.getElementById('srcLang').disabled = true;
    document.getElementById('tgtLang').disabled = true;

    // 显示进度条和日志
    document.getElementById('progressContainer').style.display = 'block';
    document.getElementById('logContainer').style.display = 'block';

    try {
        showLog('info', `[*] 开始迁移: ${srcLang} → ${tgtLang}`);
        setProgressIndeterminate(true, '迁移进行中，服务器处理中…');

        // 🔥 缩短超时时间为 3 分钟,并添加更详细的错误处理
        const response = await axios.post(buildApiUrl('/api/migrate'), {
            session_id: currentSessionId,
            src_lang: srcLang,
            tgt_lang: tgtLang
        }, {
            timeout: 480000,  // 3 分钟超时 (从 5 分钟缩短)
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const result = response.data;

        if (!result.success || !result.task_id) {
            showAlert('错误', result.error || '迁移任务创建失败', 'danger');
            showLog('error', `❌ 迁移失败: ${result.error || '迁移任务创建失败'}`);
            return;
        }

        currentMigrationTaskId = result.task_id;
        showLog('info', `[*] 迁移任务已提交: ${currentMigrationTaskId}`);
        await pollMigrationTask(currentMigrationTaskId);
        return;

        if (result.success) {
            currentMigrationId = result.migration_id;
            currentReport = result.report;

            showLog('success', `[OK] 迁移完成！`);
            showLog('success', `[*] 成功迁移: ${result.migrated_count} 个文件`);
            if (result.error_count > 0) {
                showLog('warning', `[WARN] 失败: ${result.error_count} 个文件`);
                // 显示详细错误信息
                if (result.errors && result.errors.length > 0) {
                    result.errors.forEach(err => {
                        showLog('error', `   - ${err}`);
                    });
                }
            }

            setProgressIndeterminate(false);
            updateProgress(100, '迁移完成');

            // 显示结果
            displayResults(result);

            // 标记欢迎卡片为隐藏，显示结果卡片
            document.getElementById('welcomeCard').style.display = 'none';
            document.getElementById('resultCard').style.display = 'block';
            document.getElementById('reportTabs').style.display = 'flex';

            // 生成图表
            generateCharts(result.report);

            showAlert('成功', '✅ 迁移完成', 'success');
        } else {
            showAlert('错误', result.error, 'danger');
            showLog('error', `❌ 迁移失败: ${result.error}`);
        }
    } catch (error) {
        // 🔥 增强错误处理
        let errorMessage = '未知错误';
        
        if (error.code === 'ECONNABORTED') {
            errorMessage = '请求超时 (超过 3 分钟)，可能原因：\n' +
                          '1. 项目文件过多或过大\n' +
                          '2. API 响应缓慢\n' +
                          '3. 网络连接不稳定\n\n' +
                          '建议：减少上传文件数量或检查网络连接';
        } else if (error.response) {
            // 服务器返回了错误状态码
            const status = error.response.status;
            const data = error.response.data;
            
            if (status === 400) {
                errorMessage = `请求参数错误: ${data.error || '请检查输入'}`;
            } else if (status === 404) {
                errorMessage = 'API 接口不存在，请刷新页面重试';
            } else if (status === 500) {
                errorMessage = `服务器内部错误: ${data.error || '请稍后重试'}`;
            } else {
                errorMessage = `HTTP ${status}: ${data.error || error.message}`;
            }
        } else if (error.request) {
            // 请求已发送但没有收到响应
            errorMessage = '无法连接到服务器，请检查：\n' +
                          '1. Flask 应用是否正在运行 (python app.py)\n' +
                          '2. 网络连接是否正常\n' +
                          '3. 防火墙是否阻止访问';
        } else {
            errorMessage = error.message || '发生未知错误';
        }
        
        handleError('迁移失败', { 
            message: errorMessage,
            response: error.response 
        });
    } finally {
        document.getElementById('migrateBtn').disabled = false;
        document.getElementById('srcLang').disabled = false;
        document.getElementById('tgtLang').disabled = false;
        const bar = document.getElementById('progressBar');
        const track = document.getElementById('progressTrack');
        if (bar && track && track.classList.contains('indeterminate')) {
            setProgressIndeterminate(false);
            updateProgress(0, '');
        }
    }
}

async function pollMigrationTask(taskId) {
    let pollCount = 0;
    let lastErrorCount = 0;

    while (pollCount < 720) {
        pollCount += 1;

        const response = await axios.get(buildApiUrl(`/api/migrate/${taskId}`), {
            timeout: 30000
        });
        const payload = response.data;

        if (!payload.success || !payload.task) {
            throw new Error(payload.error || '无法获取迁移任务状态');
        }

        const task = payload.task;
        updateProgress(task.progress || 0, task.message || '迁移进行中...');

        if (Array.isArray(task.errors) && task.errors.length > lastErrorCount) {
            task.errors.slice(lastErrorCount).forEach(err => {
                showLog('error', `   - ${err}`);
            });
            lastErrorCount = task.errors.length;
        }

        if (task.status === 'completed') {
            const result = task.result;
            currentMigrationId = result.migration_id;
            currentReport = result.report;

            showLog('success', '[OK] 迁移完成');
            showLog('success', `[*] 成功迁移: ${result.migrated_count} 个文件`);
            if (result.error_count > 0) {
                showLog('warning', `[WARN] 失败: ${result.error_count} 个文件`);
            }

            displayResults(result);
            document.getElementById('welcomeCard').style.display = 'none';
            document.getElementById('resultCard').style.display = 'block';
            document.getElementById('reportTabs').style.display = 'flex';
            generateCharts(result.report);
            showAlert('成功', '✅ 迁移完成', 'success');
            return;
        }

        if (task.status === 'failed') {
            throw new Error(task.error || task.message || '迁移任务失败');
        }

        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    throw new Error('迁移任务轮询超时，请稍后再查看结果');
}

// ==================== 结果显示 ====================
function displayResults(result) {
    // 更新统计信息
    document.getElementById('migratedCount').textContent = result.migrated_count;
    document.getElementById('errorCount').textContent = result.error_count;

    const report = result.report;
    document.getElementById('overallVpi').textContent = report.statistics.vpi.toFixed(3);

    // 显示漏洞统计
    document.getElementById('vulnsBefore').textContent = report.statistics.vulnerabilities_before;
    document.getElementById('vulnsAfter').textContent = report.statistics.vulnerabilities_after;

    // 显示修复率
    const fixRate = report.statistics.fix_rate;
    const fixRateBar = document.getElementById('fixRateBar');
    fixRateBar.style.width = fixRate + '%';
    document.getElementById('fixRateText').textContent = fixRate.toFixed(1) + '%';

    // 显示漏洞列表
    displayVulnerabilities(report.top_vulnerabilities.before, 'beforeVulns');
    displayVulnerabilities(report.top_vulnerabilities.after, 'afterVulns');

    // 新报告默认「迁移前」，并同步 pill 高亮
    const beforeVulnsTabBtn = document.getElementById('before-vulns-btn');
    const afterVulnsTabBtn = document.getElementById('after-vulns-btn');
    if (beforeVulnsTabBtn && afterVulnsTabBtn) {
        document.getElementById('beforeVulns').style.display = 'block';
        document.getElementById('afterVulns').style.display = 'none';
        beforeVulnsTabBtn.classList.add('active');
        afterVulnsTabBtn.classList.remove('active');
    }

    // 显示文件详情
    displayFileDetails(report.files);
}

function displayVulnerabilities(vulns, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    if (vulns.length === 0) {
        container.innerHTML = '<div class="alert alert-success">🎉 没有检测到漏洞</div>';
        return;
    }

    vulns.forEach(vuln => {
        const severity = vuln.severity || 'UNKNOWN';
        const severityColor = {
            'HIGH': 'danger',
            'MEDIUM': 'warning',
            'LOW': 'info',
            'INFO': 'secondary'
        }[severity] || 'secondary';

        const item = document.createElement('div');
        item.className = `vulnerability-item ${severity}`;
        item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <div style="flex: 1;">
                    <div><strong>${vuln.msg || '未知漏洞'}</strong></div>
                    <small class="text-muted">
                        ${vuln.rule || 'rule'} 
                        ${vuln.line ? '(Line ' + vuln.line + ')' : ''}
                    </small>
                </div>
                <span class="badge bg-${severityColor} severity-badge">${severity}</span>
            </div>
        `;
        container.appendChild(item);
    });
}

function displayFileDetails(files) {
    const table = document.getElementById('filesDetailsTable');
    table.innerHTML = '';

    files.forEach(file => {
        const status = file.status === 'success' ? 
            '<span class="badge bg-success">成功</span>' : 
            '<span class="badge bg-danger">失败</span>';

        const row = `
            <tr>
                <td>${file.path}</td>
                <td><span class="badge bg-danger">${file.before_vulns}</span></td>
                <td><span class="badge bg-info">${file.after_vulns}</span></td>
                <td><strong>${file.vpi.toFixed(3)}</strong></td>
                <td>${status}</td>
            </tr>
        `;
        table.innerHTML += row;
    });
}

// ==================== 图表绘制 ====================
function generateCharts(report) {
    // 清除现有图表
    Object.keys(charts).forEach(key => {
        if (!charts[key]) return;
        if (typeof charts[key].destroy === 'function') {
            charts[key].destroy(); // Chart.js
        } else if (typeof charts[key].dispose === 'function') {
            charts[key].dispose(); // ECharts
        }
    });
    charts = {};

    // 🔥 Chart.js 图表
    // 迁移前严重程度
    drawSeverityChart('severityBeforeChart', report.severity_breakdown.before, 'before');

    // 迁移后严重程度
    drawSeverityChart('severityAfterChart', report.severity_breakdown.after, 'after');

    // 漏洞类型对比
    drawVulnTypesChart(report.vulnerability_types);

    // 🔥 ECharts 高级图表
    // 1. 整体安全评分仪表盘
    drawSafetyGaugeChart(report.statistics.vpi);

    // 2. 多维度安全评估雷达图
    drawRadarChart(report);

    // 3. 各文件VPI对比柱状图
    drawFileVpiChart(report.files);
}

function drawSeverityChart(containerId, severity, type) {
    const ctx = document.getElementById(containerId);
    if (!ctx) return;

    const labels = Object.keys(severity);
    const data = Object.values(severity);
    const backgroundColor = labels.map(label => {
        const mapping = {
            'HIGH': '#f87171',
            'MEDIUM': '#fbbf24',
            'LOW': '#34d399',
            'INFO': '#64748b'
        };
        return mapping[label] || '#64748b';
    });

    charts[containerId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColor,
                borderColor: 'rgba(14, 18, 32, 0.9)',
                borderWidth: 2
            }]
        },
        options: {
            color: '#c8d0e0',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#8b95a8', font: { size: 11 } }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            return context.label + ': ' + context.parsed;
                        }
                    }
                }
            }
        }
    });
}

function drawVulnTypesChart(vulnerability_types) {
    const chartDom = document.getElementById('vulnTypesChart');
    if (!chartDom) return;

    const before = vulnerability_types.before || {};
    const after = vulnerability_types.after || {};

    const allTypes = new Set([...Object.keys(before), ...Object.keys(after)]);
    const labels = Array.from(allTypes);
    const beforeData = labels.map(type => before[type] || 0);
    const afterData = labels.map(type => after[type] || 0);
    const chart = echarts.init(chartDom);
    const beforePieData = labels
        .map((type, idx) => ({ name: type, value: beforeData[idx] }))
        .filter(item => item.value > 0);
    const afterPieData = labels
        .map((type, idx) => ({ name: type, value: afterData[idx] }))
        .filter(item => item.value > 0);

    const option = labels.length === 0
        ? {
            title: {
                text: '暂无漏洞类型数据',
                left: 'center',
                top: 'center',
                textStyle: { color: '#8b95a8', fontSize: 14, fontWeight: 'normal' }
            },
            xAxis: { show: false },
            yAxis: { show: false },
            series: []
        }
        : {
            tooltip: {
                trigger: 'item',
                formatter: '{a}<br/>{b}: {c} ({d}%)'
            },
            legend: {
                top: 0,
                type: 'scroll',
                textStyle: { color: '#8b95a8' }
            },
            color: ['#f87171', '#34d399', '#fbbf24', '#60a5fa', '#a78bfa', '#22d3ee', '#f97316', '#94a3b8'],
            title: [
                {
                    text: '迁移前',
                    left: '25%',
                    top: '10%',
                    textAlign: 'center',
                    textStyle: { color: '#8b95a8', fontSize: 12, fontWeight: 'normal' }
                },
                {
                    text: '迁移后',
                    left: '75%',
                    top: '10%',
                    textAlign: 'center',
                    textStyle: { color: '#8b95a8', fontSize: 12, fontWeight: 'normal' }
                }
            ],
            series: [
                {
                    name: '迁移前',
                    type: 'pie',
                    radius: ['35%', '62%'],
                    center: ['25%', '58%'],
                    label: { color: '#c8d0e0', formatter: '{b}: {c}' },
                    labelLine: { lineStyle: { color: '#8b95a8' } },
                    data: beforePieData.length ? beforePieData : [{ name: '无数据', value: 1, itemStyle: { color: 'rgba(148,163,184,0.35)' } }]
                },
                {
                    name: '迁移后',
                    type: 'pie',
                    radius: ['35%', '62%'],
                    center: ['75%', '58%'],
                    label: { color: '#c8d0e0', formatter: '{b}: {c}' },
                    labelLine: { lineStyle: { color: '#8b95a8' } },
                    data: afterPieData.length ? afterPieData : [{ name: '无数据', value: 1, itemStyle: { color: 'rgba(148,163,184,0.35)' } }]
                }
            ]
        };

    chart.setOption(option);
    charts['vulnTypesChart'] = chart;
}

// ==================== ECharts 高级图表 ====================

/**
 * 绘制整体安全评分仪表盘
 */
function drawSafetyGaugeChart(vpi) {
    const chartDom = document.getElementById('safetyGaugeChart');
    if (!chartDom) return;

    const myChart = echarts.init(chartDom);
    
    // VPI 越低越好,转换为安全评分 (0-100)
    const safetyScore = Math.max(0, Math.min(100, (1 - vpi) * 100));
    
    const axisBand = 14;
    const option = {
        series: [
            {
                type: 'gauge',
                startAngle: 180,
                endAngle: 0,
                min: 0,
                max: 100,
                splitNumber: 5,
                /* 略缩小半径，给左右两端刻度留出边距，避免被容器裁切 */
                radius: '72%',
                center: ['50%', '58%'],
                itemStyle: {
                    color: safetyScore >= 80 ? '#34d399' : safetyScore >= 60 ? '#fbbf24' : '#f87171'
                },
                progress: {
                    show: true,
                    width: axisBand
                },
                pointer: {
                    show: true,
                    length: '60%',
                    width: 5
                },
                axisLine: {
                    lineStyle: {
                        width: axisBand
                    }
                },
                axisTick: {
                    distance: -(axisBand + 2),
                    splitNumber: 5,
                    lineStyle: {
                        width: 2,
                        color: 'rgba(139, 149, 168, 0.5)'
                    }
                },
                splitLine: {
                    distance: -(axisBand + 6),
                    length: 12,
                    lineStyle: {
                        width: 3,
                        color: 'rgba(139, 149, 168, 0.35)'
                    }
                },
                /* 刻度在弧内侧（朝圆心），避免 0/100 与粗半圆弧重叠被挡 */
                axisLabel: {
                    inside: true,
                    distance: -22,
                    color: '#b8c4d8',
                    fontSize: 12,
                    fontWeight: 500
                },
                anchor: {
                    show: true,
                    showAbove: true,
                    size: 20,
                    itemStyle: {
                        borderWidth: 5
                    }
                },
                title: {
                    show: true,
                    offsetCenter: [0, '70%'],
                    fontSize: 16,
                    color: '#8b95a8'
                },
                detail: {
                    valueAnimation: true,
                    fontSize: 30,
                    offsetCenter: [0, '30%'],
                    formatter: '{value}分',
                    color: safetyScore >= 80 ? '#34d399' : safetyScore >= 60 ? '#fbbf24' : '#f87171'
                },
                data: [
                    {
                        value: safetyScore.toFixed(1),
                        name: '安全评分'
                    }
                ]
            }
        ]
    };

    myChart.setOption(option);
    charts['safetyGaugeChart'] = myChart;
}

/**
 * 绘制多维度安全评估雷达图
 */
function drawRadarChart(report) {
    const chartDom = document.getElementById('radarChart');
    if (!chartDom) return;

    const myChart = echarts.init(chartDom);
    
    const stats = report.statistics;
    const files = report.files || [];
    
    // 计算各维度得分
    const vpiScore = Math.max(0, (1 - stats.vpi) * 100);
    const fixRateScore = stats.fix_rate || 0;
    
    // 计算文件迁移成功率
    const successFiles = files.filter(f => f.status === 'success').length;
    const successRate = files.length > 0 ? (successFiles / files.length * 100) : 0;
    
    // 计算平均漏洞减少率
    const avgReduction = files.length > 0 ? 
        files.reduce((sum, f) => sum + (f.before_vulns > 0 ? 
            ((f.before_vulns - f.after_vulns) / f.before_vulns * 100) : 100), 0) / files.length : 0;
    
    const option = {
        radar: {
            indicator: [
                { name: 'VPI指数', max: 100 },
                { name: '修复率', max: 100 },
                { name: '迁移成功率', max: 100 },
                { name: '漏洞减少率', max: 100 },
                { name: '综合评分', max: 100 }
            ],
            shape: 'polygon',
            splitNumber: 4,
            axisName: {
                color: '#8b95a8',
                fontSize: 11
            },
            splitLine: {
                lineStyle: {
                    color: 'rgba(255,255,255,0.08)'
                }
            },
            splitArea: {
                show: true,
                areaStyle: {
                    color: ['rgba(0, 212, 255, 0.06)', 'rgba(167, 139, 250, 0.08)']
                }
            }
        },
        series: [
            {
                type: 'radar',
                data: [
                    {
                        value: [
                            vpiScore.toFixed(1),
                            fixRateScore.toFixed(1),
                            successRate.toFixed(1),
                            Math.max(0, avgReduction).toFixed(1),
                            ((vpiScore + fixRateScore + successRate + Math.max(0, avgReduction)) / 4).toFixed(1)
                        ],
                        name: '安全评估',
                        areaStyle: {
                            color: 'rgba(0, 212, 255, 0.22)'
                        },
                        lineStyle: {
                            color: '#00d4ff',
                            width: 2
                        },
                        itemStyle: {
                            color: '#00d4ff'
                        }
                    }
                ]
            }
        ]
    };

    myChart.setOption(option);
    charts['radarChart'] = myChart;
}

/**
 * 绘制各文件VPI对比柱状图
 */
function drawFileVpiChart(files) {
    const chartDom = document.getElementById('fileVpiChart');
    if (!chartDom) return;

    const myChart = echarts.init(chartDom);
    
    // 提取文件名和VPI值
    const fileNames = files.map(f => {
        const parts = f.path.split('\\');
        return parts[parts.length - 1]; // 只显示文件名
    });
    const vpiValues = files.map(f => f.vpi);
    
    // 根据VPI值设置颜色
    const colors = vpiValues.map(vpi => {
        if (vpi <= 0.2) return '#34d399';
        if (vpi <= 0.5) return '#fbbf24';
        return '#f87171';
    });
    
    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: {
                type: 'shadow'
            },
            formatter: function(params) {
                const vpi = params[0].value;
                let assessment = vpi <= 0.2 ? '优秀' : vpi <= 0.5 ? '良好' : '需改进';
                return `${params[0].name}<br/>VPI: ${vpi.toFixed(3)}<br/>评估: ${assessment}`;
            }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '15%',
            top: '10%',
            containLabel: true
        },
        xAxis: {
            type: 'category',
            data: fileNames,
            axisLabel: {
                rotate: 30,
                interval: 0,
                fontSize: 11,
                color: '#8b95a8'
            }
        },
        yAxis: {
            type: 'value',
            name: 'VPI值',
            min: 0,
            max: 1,
            nameTextStyle: { color: '#8b95a8' },
            axisLabel: { color: '#8b95a8' },
            splitLine: {
                lineStyle: {
                    type: 'dashed',
                    color: 'rgba(255,255,255,0.08)'
                }
            }
        },
        series: [
            {
                type: 'bar',
                data: vpiValues.map((vpi, idx) => ({
                    value: vpi,
                    itemStyle: {
                        color: colors[idx]
                    }
                })),
                barWidth: '60%',
                label: {
                    show: true,
                    position: 'top',
                    formatter: '{c}',
                    fontSize: 11
                }
            }
        ]
    };

    myChart.setOption(option);
    charts['fileVpiChart'] = myChart;
}

// ==================== 下载 ====================
async function downloadProject() {
    if (!currentMigrationId) {
        showAlert('错误', '没有可下载的项目', 'danger');
        return;
    }

    try {
        showLog('info', '📥 正在下载项目文件...');
        const response = await axios.get(buildApiUrl(`/api/download/${currentMigrationId}`), {
            responseType: 'blob'
        });

        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `migrated_project_${currentMigrationId.slice(0, 8)}.zip`);
        document.body.appendChild(link);
        link.click();
        link.remove();

        showLog('success', '[OK] 项目文件下载完成');
        showAlert('成功', '[OK] 项目文件下载完成', 'success');
    } catch (error) {
        handleError('下载失败', error);
    }
}

async function downloadReport() {
    if (!currentMigrationId) {
        showAlert('错误', '没有可下载的报告', 'danger');
        return;
    }

    try {
        showLog('info', '[*] 正在下载报告...');
        const response = await axios.get(buildApiUrl(`/api/download-report/${currentMigrationId}`), {
            responseType: 'blob'
        });

        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `migration_report_${currentMigrationId.slice(0, 8)}.json`);
        document.body.appendChild(link);
        link.click();
        link.remove();

        showLog('success', '[OK] 报告下载完成');
        showAlert('成功', '[OK] 报告下载完成', 'success');
    } catch (error) {
        handleError('下载报告失败', error);
    }
}

// ==================== 加载语言列表 ====================
async function loadLanguages() {
    try {
        const response = await axios.get(buildApiUrl('/api/languages'));
        const languages = response.data.languages;

        // 填充下拉列表
        const srcSelect = document.getElementById('srcLang');
        const tgtSelect = document.getElementById('tgtLang');

        languages.forEach(lang => {
            srcSelect.innerHTML += `<option value="${lang}">${lang.toUpperCase()}</option>`;
            tgtSelect.innerHTML += `<option value="${lang}">${lang.toUpperCase()}</option>`;
        });
    } catch (error) {
        console.error('加载语言失败:', error);
    }
}

// ==================== 工具函数 ====================
function setProgressIndeterminate(active, text) {
    const track = document.getElementById('progressTrack');
    const bar = document.getElementById('progressBar');
    const label = document.getElementById('progressText');
    if (!track || !bar) return;

    if (active) {
        track.classList.add('indeterminate');
        bar.classList.add('indeterminate-bar');
        bar.style.width = '0%';
        bar.textContent = '';
        if (text && label) label.textContent = text;
    } else {
        track.classList.remove('indeterminate');
        bar.classList.remove('indeterminate-bar');
    }
}

function updateProgress(percentage, text) {
    const track = document.getElementById('progressTrack');
    const bar = document.getElementById('progressBar');
    const label = document.getElementById('progressText');
    if (!bar) return;

    setProgressIndeterminate(false);
    const pct = Math.min(100, Math.max(0, Math.round(Number(percentage) || 0)));
    bar.style.width = pct + '%';
    bar.textContent = pct + '%';
    if (label) label.textContent = text || '';
}

function showLog(type, message) {
    const logBox = document.getElementById('logBox');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const time = new Date().toLocaleTimeString('zh-CN');
    entry.textContent = `[${time}] ${message}`;
    logBox.appendChild(entry);
    logBox.scrollTop = logBox.scrollHeight;
}

function showAlert(title, message, type) {
    // 创建 Toast 容器（如果不存在）
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999;';
        document.body.appendChild(toastContainer);
    }

    // 创建 Toast
    const toastId = 'toast_' + Date.now();
    const bgColor = {
        'success': 'bg-success',
        'danger': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-info';

    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `toast ${bgColor} text-white`;
    toast.style.cssText = 'margin-bottom: 10px;';
    toast.innerHTML = `
        <div class="toast-body">
            <strong>${title}</strong>
            <button type="button" class="btn-close btn-close-white" onclick="document.getElementById('${toastId}').remove()"></button>
        </div>
        <div class="toast-body">${message}</div>
    `;
    toastContainer.appendChild(toast);

    // 3 秒后自动移除
    setTimeout(() => {
        const elem = document.getElementById(toastId);
        if (elem) elem.remove();
    }, 3000);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function handleError(title, error) {
    const message = error.response?.data?.error || error.message || '未知错误';
    showAlert(title, message, 'danger');
    showLog('error', `❌ ${title}: ${message}`);
    console.error(error);
}
