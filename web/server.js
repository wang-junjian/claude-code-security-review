const http = require('http');
const fs = require('fs');
const path = require('path');

// 评估结果目录
const EVAL_RESULTS_DIR = path.join(__dirname, '../eval_results');
// 静态文件目录
const STATIC_DIR = __dirname;

// 解析文件名获取类型、仓库和PR号
function parseFilename(filename) {
    const match = filename.match(/^(pr|repo)_(.*?)(?:_(\d+))?\.json$/);
    if (match) {
        const type = match[1]; // 'pr' 或 'repo'
        let repoName = match[2];
        const prNumber = match[3] ? parseInt(match[3]) : 0;

        // 将下划线转换为斜杠，还原仓库名格式 (如 anthropics/claude-code-security-review)
        repoName = repoName.replace(/_/g, '/');

        return {
            type,
            repo_name: repoName,
            pr_number: prNumber
        };
    }
    return null;
}

// 读取并解析所有JSON文件
function parseAllResults() {
    const results = [];

    try {
        // 读取目录
        const files = fs.readdirSync(EVAL_RESULTS_DIR);

        // 过滤JSON文件
        const jsonFiles = files.filter(file => file.endsWith('.json') && file !== 'results.json');

        console.log(`找到 ${jsonFiles.length} 个评估结果文件`);

        // 解析每个JSON文件
        jsonFiles.forEach(file => {
            try {
                const filePath = path.join(EVAL_RESULTS_DIR, file);
                const data = fs.readFileSync(filePath, 'utf8');
                const jsonData = JSON.parse(data);

                // 解析文件名信息
                const fileInfo = parseFilename(path.basename(file));
                if (fileInfo) {
                    // 合并信息
                    const result = {
                        id: `${fileInfo.type}_${fileInfo.repo_name}_${fileInfo.pr_number}`,
                        ...fileInfo,
                        ...jsonData
                    };

                    results.push(result);
                    console.log(`解析成功: ${file}`);
                } else {
                    console.warn(`无法解析文件名: ${file}`);
                }
            } catch (error) {
                console.error(`解析文件失败 ${file}: ${error.message}`);
            }
        });

        return results;
    } catch (error) {
        console.error(`处理评估结果时出错: ${error.message}`);
        return [];
    }
}

// 创建HTTP服务器
const server = http.createServer((req, res) => {
    // 设置CORS头
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // 处理预检请求
    if (req.method === 'OPTIONS') {
        res.statusCode = 200;
        res.end();
        return;
    }

    // 路由处理
    if (req.method === 'GET') {
        // 获取所有评估结果
        if (req.url === '/api/results') {
            const results = parseAllResults();
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results, null, 2));
            return;
        }

        // 获取文档内容
        if (req.url.startsWith('/api/docs/custom-filtering')) {
            const docsPath = path.join(__dirname, '../docs/custom-filtering-instructions.md');
            console.log('Looking for docs at:', docsPath);
            if (fs.existsSync(docsPath)) {
                const content = fs.readFileSync(docsPath, 'utf8');
                res.setHeader('Content-Type', 'text/plain');
                res.end(content);
            } else {
                res.statusCode = 404;
                res.end('Not Found');
            }
            return;
        }

        if (req.url.startsWith('/api/docs/custom-scan')) {
            const docsPath = path.join(__dirname, '../docs/custom-security-scan-instructions.md');
            console.log('Looking for docs at:', docsPath);
            if (fs.existsSync(docsPath)) {
                const content = fs.readFileSync(docsPath, 'utf8');
                res.setHeader('Content-Type', 'text/plain');
                res.end(content);
            } else {
                res.statusCode = 404;
                res.end('Not Found');
            }
            return;
        }

        // 获取示例内容
        if (req.url.startsWith('/api/examples/custom-filtering')) {
            const examplesPath = path.join(__dirname, '../examples/custom-false-positive-filtering.txt');
            console.log('Looking for examples at:', examplesPath);
            if (fs.existsSync(examplesPath)) {
                const content = fs.readFileSync(examplesPath, 'utf8');
                res.setHeader('Content-Type', 'text/plain');
                res.end(content);
            } else {
                res.statusCode = 404;
                res.end('Not Found');
            }
            return;
        }

        if (req.url.startsWith('/api/examples/custom-scan')) {
            const examplesPath = path.join(__dirname, '../examples/custom-security-scan-instructions.txt');
            console.log('Looking for examples at:', examplesPath);
            if (fs.existsSync(examplesPath)) {
                const content = fs.readFileSync(examplesPath, 'utf8');
                res.setHeader('Content-Type', 'text/plain');
                res.end(content);
            } else {
                res.statusCode = 404;
                res.end('Not Found');
            }
            return;
        }

        // 获取 security-review 命令配置
        if (req.url.startsWith('/api/security-review')) {
            const commandPath = path.join(__dirname, '../.claude/commands/security-review.md');
            console.log('Looking for security-review command at:', commandPath);
            if (fs.existsSync(commandPath)) {
                const content = fs.readFileSync(commandPath, 'utf8');
                res.setHeader('Content-Type', 'text/plain');
                res.end(content);
            } else {
                res.statusCode = 404;
                res.end('Not Found');
            }
            return;
        }

        // 提供静态文件
        if (req.url === '/' || req.url === '/index.html') {
            const filePath = path.join(STATIC_DIR, 'index.html');
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                res.setHeader('Content-Type', 'text/html');
                res.end(content);
                return;
            }
        }
    } else if (req.method === 'POST') {
        // 保存编辑后的示例内容
        if (req.url === '/api/examples/custom-filtering') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    const examplesPath = path.join(__dirname, '../examples/custom-false-positive-filtering.txt');
                    fs.writeFileSync(examplesPath, data.content, 'utf8');
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ success: true }));
                } catch (error) {
                    console.error('保存文件失败:', error);
                    res.statusCode = 500;
                    res.end('Internal Server Error');
                }
            });
            return;
        }

        if (req.url === '/api/examples/custom-scan') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    const examplesPath = path.join(__dirname, '../examples/custom-security-scan-instructions.txt');
                    fs.writeFileSync(examplesPath, data.content, 'utf8');
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ success: true }));
                } catch (error) {
                    console.error('保存文件失败:', error);
                    res.statusCode = 500;
                    res.end('Internal Server Error');
                }
            });
            return;
        }

        // 保存 security-review 命令配置
        if (req.url === '/api/security-review') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    const commandPath = path.join(__dirname, '../.claude/commands/security-review.md');
                    fs.writeFileSync(commandPath, data.content, 'utf8');
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ success: true }));
                } catch (error) {
                    console.error('保存文件失败:', error);
                    res.statusCode = 500;
                    res.end('Internal Server Error');
                }
            });
            return;
        }
    }

    // 404错误
    res.statusCode = 404;
    res.end('Not Found');
});

// 启动服务器
const PORT = process.env.PORT || 8081;
server.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
    console.log(`访问 http://localhost:${PORT} 查看安全评估结果`);
    console.log('服务器会实时读取 eval_results 目录中的评估结果文件');
    console.log('按 Ctrl+C 停止服务器');
});
