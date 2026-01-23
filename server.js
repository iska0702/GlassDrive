require('dotenv').config();
const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn, execSync, exec } = require('child_process');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const https = require('https'); // For OpenAI calls

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;
const STORAGE_DIR = path.join(ROOT_DIR, 'glassdrive');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_do_not_use_in_prod';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Ensure storage root exists
if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR);
    console.log(`Created storage directory: ${STORAGE_DIR}`);
}

// === MIDDLEWARE ===

// 1. Security Headers
app.use(helmet({
    contentSecurityPolicy: false, // Disabling CSP for now to avoid breaking inline scripts/styles in main.html. In a real prod app, strict CSP is recommended.
}));

// 2. CORS (Allow all for local dev, restrictive in prod)
app.use(cors({
    origin: true, // Reflect request origin
    credentials: true
}));

// 3. Body Parsing
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 4. Rate Limiting for Auth
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many login attempts, please try again later'
});

// 5. Block direct access to storage folder via static file serving
app.get('/glassdrive', (req, res) => {
    res.status(403).send('Доступ запрещен');
});

// 6. Serve Static Files (main.html, etc.)
app.use(express.static(ROOT_DIR, { index: 'main.html' }));

// === HELPERS ===

function sanitizeName(name) {
    if (!name) return 'unknown';
    return name.replace(/[^a-z0-9@._-]/gi, '_').toLowerCase();
}

function generateToken(user) {
    return jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
}

// Auth Middleware
// Auth Middleware
function authenticateToken(req, res, next) {
    // 1. Check Cookie
    let token = req.cookies.auth_token;

    // 2. Check Authorization Header (Bearer)
    const authHeader = req.headers['authorization'];
    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    // 3. Check Query Param (for downloads/images)
    if (!token && req.query.token) {
        token = req.query.token;
    }

    if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden: Invalid token' });
        req.user = user;
        next();
    });
}

// === AUTH ENDPOINTS ===

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { email, password, name, rememberMe } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Требуется Email и пароль' });
        }

        const safeName = sanitizeName(email);
        const userDir = path.join(STORAGE_DIR, safeName);
        const userFilesDir = path.join(userDir, 'files');

        if (fs.existsSync(userDir)) {
            return res.status(409).json({ error: 'Пользователь уже существует' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        fs.mkdirSync(userDir, { recursive: true });
        fs.mkdirSync(userFilesDir, { recursive: true });

        const userData = {
            email,
            password: hashedPassword,
            name,
            createdAt: new Date()
        };

        fs.writeFileSync(path.join(userDir, 'user.json'), JSON.stringify(userData, null, 2));

        // Auto login
        const token = generateToken(userData);

        if (rememberMe) {
            res.cookie('auth_token', token, {
                httpOnly: true,
                secure: false, // Set true if using HTTPS
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });
        } else {
            res.clearCookie('auth_token');
        }

        res.status(200).json({ success: true, message: 'Пользователь зарегистрирован', token, user: { name, email } });
        console.log(`Registered user: ${email}`);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Требуется Email и пароль' });
        }

        const safeName = sanitizeName(email);
        const userDir = path.join(STORAGE_DIR, safeName);
        const userJsonPath = path.join(userDir, 'user.json');

        if (!fs.existsSync(userJsonPath)) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        const savedData = JSON.parse(fs.readFileSync(userJsonPath));
        const match = await bcrypt.compare(password, savedData.password);

        if (match) {
            const token = generateToken(savedData);

            if (rememberMe) {
                res.cookie('auth_token', token, {
                    httpOnly: true,
                    secure: false, // Set true if using HTTPs
                    sameSite: 'Strict',
                    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
                });
            } else {
                res.clearCookie('auth_token');
            }

            res.status(200).json({ success: true, token, name: savedData.name, email: savedData.email });
        } else {
            // Check legacy plain text password (migration support)
            if (savedData.password === password) {
                // Re-hash and save
                const hashedPassword = await bcrypt.hash(password, 10);
                savedData.password = hashedPassword;
                fs.writeFileSync(userJsonPath, JSON.stringify(savedData, null, 2));

                const token = generateToken(savedData);

                if (rememberMe) {
                    res.cookie('auth_token', token, { httpOnly: true, sameSite: 'Strict' });
                } else {
                    res.clearCookie('auth_token');
                }

                return res.status(200).json({ success: true, token, name: savedData.name, email: savedData.email });
            }

            res.status(401).json({ error: 'Неверный пароль' });
        }

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера при входе' });
    }
});

app.post('/api/user/update', authenticateToken, async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const currentUserEmail = req.user.email;

        // Verify email matches (optional safety check, though we use req.user.email mostly)
        // If we want to allow email change, that's complex (need to rename folders). 
        // For now, let's restrict email changes or just ignore `email` from body if we don't want to support it yet.
        // Implementation Plan said "Populate Name and Email fields". 
        // Let's allow updating Name and Password.

        const safeName = sanitizeName(currentUserEmail);
        const userDir = path.join(STORAGE_DIR, safeName);
        const userJsonPath = path.join(userDir, 'user.json');

        if (!fs.existsSync(userJsonPath)) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const userData = JSON.parse(fs.readFileSync(userJsonPath));

        // Update Name
        if (name) userData.name = name;

        // Update Password
        if (password && password.trim().length > 0) {
            const hashedPassword = await bcrypt.hash(password, 10);
            userData.password = hashedPassword;
        }

        fs.writeFileSync(userJsonPath, JSON.stringify(userData, null, 2));

        // Return updated info
        res.status(200).json({
            success: true,
            message: 'Профиль обновлен',
            user: { name: userData.name, email: userData.email }
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка обновления' });
    }
});


app.get('/api/file', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const { path: filePath } = req.query;

    if (!filePath) return res.status(400).json({ error: 'Требуется путь' });

    const safeName = sanitizeName(email);
    const safeFilePath = filePath.replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const fullPath = path.join(STORAGE_DIR, safeName, 'files', safeFilePath);

    if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'Файл не найден' });

    // Check if directory
    if (fs.statSync(fullPath).isDirectory()) return res.status(400).json({ error: 'Невозможно скачать папку напрямую' });

    // Determine Content-Disposition based on extension
    const ext = path.extname(fullPath).toLowerCase();
    const inlineTypes = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mov', '.webm', '.pdf', '.txt', '.md', '.json', '.js', '.css', '.html'];

    if (inlineTypes.includes(ext)) {
        res.sendFile(fullPath);
    } else {
        res.download(fullPath);
    }
});

app.post('/api/logout', (req, res) => {

    res.clearCookie('auth_token');
    res.status(200).json({ success: true, message: 'Вы вышли' });
});

app.get('/api/check-auth', authenticateToken, (req, res) => {
    res.status(200).json({ authenticated: true, user: req.user });
});

// === FILE ENDPOINTS (Protected) ===


const ADMIN_EMAIL = 'admin@glassdrive.com';

/* HELPER: Get Storage User (Admin Masquerade) */
function getStorageUser(req) {
    if (req.user.email === ADMIN_EMAIL) {
        // Admin can impersonate via query 'targetUser' or body 'targetUser'
        const target = req.query.targetUser || req.body.targetUser;
        if (target) return target;
    }
    return req.user.email;
}

// === ADMIN ENDPOINTS ===
app.get('/api/admin/users', authenticateToken, (req, res) => {
    if (req.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'Только для администратора' });

    try {
        const entries = fs.readdirSync(STORAGE_DIR).map(dir => {
            const userJsonPath = path.join(STORAGE_DIR, dir, 'user.json');
            if (fs.existsSync(userJsonPath)) {
                try {
                    const data = JSON.parse(fs.readFileSync(userJsonPath));
                    return {
                        email: data.email,
                        name: data.name,
                        safeName: dir,
                        createdAt: data.createdAt
                    };
                } catch (e) { return null; }
            }
            return null;
        }).filter(u => u !== null && u.email !== ADMIN_EMAIL);
        res.status(200).json(entries);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Не удалось получить список пользователей' });
    }
});

app.delete('/api/admin/user', authenticateToken, (req, res) => {
    if (req.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: 'Только для администратора' });

    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Требуется Email' });
    if (email === ADMIN_EMAIL) return res.status(400).json({ error: 'Невозможно удалить администратора' });

    const safeName = sanitizeName(email);
    const userDir = path.join(STORAGE_DIR, safeName);

    if (!fs.existsSync(userDir)) return res.status(404).json({ error: 'Пользователь не найден' });

    try {
        fs.rmSync(userDir, { recursive: true, force: true });
        res.status(200).json({ success: true, message: 'Пользователь удален' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Не удалось удалить пользователя' });
    }
});

// === FILE ENDPOINTS (Protected) ===

app.get('/api/files', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const subDir = req.query.path || '';

    const safeName = sanitizeName(email);
    // Prevent directory traversal
    const safeSubDir = subDir.replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const userFilesDir = path.join(STORAGE_DIR, safeName, 'files', safeSubDir);

    if (!fs.existsSync(userFilesDir)) {
        return res.status(200).json([]); // Return empty if user folder doesn't exist yet or path invalid
    }

    try {
        const files = fs.readdirSync(userFilesDir).map(file => {
            const stats = fs.statSync(path.join(userFilesDir, file));
            return {
                name: file,
                isDirectory: stats.isDirectory(),
                size: stats.size,
                mtime: stats.mtime
            };
        });
        res.status(200).json(files);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Не удалось получить список файлов' });
    }
});

app.post('/api/folders', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const folderPath = req.body.path;

    if (!folderPath) return res.status(400).json({ error: 'Требуется путь' });

    const safeName = sanitizeName(email);
    const safeFolderPath = folderPath.replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const targetDir = path.join(STORAGE_DIR, safeName, 'files', safeFolderPath);

    if (fs.existsSync(targetDir)) {
        return res.status(409).json({ error: 'Папка уже существует' });
    }

    try {
        fs.mkdirSync(targetDir, { recursive: true });
        res.status(200).json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось создать папку' });
    }
});

app.post('/api/rename', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const { path: folderPath, oldName, newName } = req.body;

    if (!oldName || !newName) return res.status(400).json({ error: 'Требуются имена' });
    if (oldName.includes('..') || newName.includes('..') || newName.includes('/')) {
        return res.status(400).json({ error: 'Неверное имя' });
    }

    const safeName = sanitizeName(email);
    const safeFolderPath = (folderPath || '').replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const userFilesDir = path.join(STORAGE_DIR, safeName, 'files', safeFolderPath);

    const oldPath = path.join(userFilesDir, oldName);
    const newPath = path.join(userFilesDir, newName);

    if (!fs.existsSync(oldPath)) return res.status(404).json({ error: 'Источник не найден' });
    if (fs.existsSync(newPath)) return res.status(409).json({ error: 'Имя занято' });

    try {
        fs.renameSync(oldPath, newPath);
        res.status(200).json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка переименования' });
    }
});

app.delete('/api/files', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const { filename, path: folderPath } = req.body;

    if (!filename) return res.status(400).json({ error: 'Требуется имя файла' });

    const safeName = sanitizeName(email);
    const safeFolderPath = (folderPath || '').replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const safeFilename = path.basename(filename);

    const userFilesDir = path.join(STORAGE_DIR, safeName, 'files', safeFolderPath);
    const filePath = path.join(userFilesDir, safeFilename);

    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Файл не найден' });

    try {
        if (fs.statSync(filePath).isDirectory()) {
            fs.rmSync(filePath, { recursive: true, force: true });
        } else {
            fs.unlinkSync(filePath);
        }
        res.status(200).json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка удаления' });
    }
});

app.post('/api/upload', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const filename = req.headers['x-filename'];
    const uploadPath = req.headers['x-path'] || '';

    if (!filename) return res.status(400).json({ error: 'Требуется заголовок имени файла' });

    const decodedFilename = decodeURIComponent(filename);
    const safeName = sanitizeName(email);
    const safeUploadPath = uploadPath.replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const userFilesDir = path.join(STORAGE_DIR, safeName, 'files', safeUploadPath);

    if (!fs.existsSync(userFilesDir)) {
        fs.mkdirSync(userFilesDir, { recursive: true });
    }

    const safeFilename = path.basename(decodedFilename);
    const filePath = path.join(userFilesDir, safeFilename);
    const writable = fs.createWriteStream(filePath);

    req.pipe(writable);

    writable.on('finish', () => {
        res.status(200).json({ success: true });
    });

    writable.on('error', (err) => {
        console.error('Upload error', err);
        res.status(500).json({ error: 'Ошибка загрузки' });
    });
});

app.get('/api/download-all', authenticateToken, (req, res) => {
    const email = getStorageUser(req);
    const subDir = req.query.path || '';

    const safeName = sanitizeName(email);
    const safeFolderPath = subDir.replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const userFilesDir = path.join(STORAGE_DIR, safeName, 'files', safeFolderPath);

    if (!fs.existsSync(userFilesDir)) return res.status(404).json({ error: 'Не найдено' });

    const zipName = safeFolderPath ? `${path.basename(userFilesDir)}.zip` : 'files.zip';
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);

    const zip = spawn('zip', ['-r', '-', '.'], { cwd: userFilesDir });
    zip.stdout.pipe(res);
    zip.stderr.on('data', d => console.error(`zip err: ${d}`));
    zip.on('close', code => {
        if (code !== 0) console.error(`zip exited with ${code}`);
    });
});

app.post('/api/favorites', authenticateToken, (req, res) => {
    const email = req.user.email;
    const { path: itemPath } = req.body;

    if (!itemPath) return res.status(400).json({ error: 'Требуется путь' });

    const safeName = sanitizeName(email);
    const userDir = path.join(STORAGE_DIR, safeName);
    const favFile = path.join(userDir, 'favorites.json');

    let favorites = [];
    if (fs.existsSync(favFile)) favorites = JSON.parse(fs.readFileSync(favFile));

    const index = favorites.indexOf(itemPath);
    let isFavorite = false;
    if (index === -1) {
        favorites.push(itemPath);
        isFavorite = true;
    } else {
        favorites.splice(index, 1);
    }

    fs.writeFileSync(favFile, JSON.stringify(favorites, null, 2));
    res.status(200).json({ success: true, isFavorite });
});

app.get('/api/favorites', authenticateToken, (req, res) => {
    const email = req.user.email;
    const safeName = sanitizeName(email);
    const userDir = path.join(STORAGE_DIR, safeName);
    const favFile = path.join(userDir, 'favorites.json');

    if (!fs.existsSync(favFile)) return res.status(200).json([]);

    const favorites = JSON.parse(fs.readFileSync(favFile));
    const detailed = [];
    const userFilesRoot = path.join(userDir, 'files');

    favorites.forEach(favPath => {
        if (favPath.includes('..')) return;
        const fullPath = path.join(userFilesRoot, favPath);
        if (fs.existsSync(fullPath)) {
            try {
                const stats = fs.statSync(fullPath);
                detailed.push({
                    name: path.basename(favPath),
                    path: favPath,
                    isDirectory: stats.isDirectory(),
                    size: stats.size,
                    mtime: stats.mtime,
                    isFavorite: true
                });
            } catch (e) { }
        }
    });

    res.status(200).json(detailed);
});

app.get('/api/archive/inspect', authenticateToken, (req, res) => {
    const email = req.user.email;
    const pathParam = req.query.path || req.query.filename; // Support both
    if (!pathParam) return res.status(400).json({ error: 'Требуется путь к файлу' });

    const safeName = sanitizeName(email);
    // Secure path handling
    const safeFilePath = pathParam.replace(/\.\./g, '').split('/').filter(p => p.length > 0).join('/');
    const filePath = path.join(STORAGE_DIR, safeName, 'files', safeFilePath);

    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Файл не найден' });

    const ext = path.extname(filePath).toLowerCase();
    let command = "";
    let parser = "zip";

    if (ext === '.zip') { command = `unzip -l "${filePath}"`; parser = 'zip'; }
    else if (ext === '.7z' || ext === '.rar') { command = `7z l "${filePath}"`; parser = '7z'; }
    else if (/\.t(ar|gz|bz2|xz)$/.test(ext)) { command = `tar -tvf "${filePath}"`; parser = 'tar'; }
    else return res.status(400).json({ error: 'Unsupported format' });

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error("Archive exec error:", stderr);
            return res.status(500).json({ error: 'Не удалось прочитать архив (возможно, не установлен 7z/unzip)' });
        }

        const lines = stdout.split('\n');
        const entries = [];

        if (parser === 'zip') {
            let parsing = false;
            for (const line of lines) {
                if (line.includes('Length') && line.includes('Name')) { parsing = true; continue; }
                if (line.startsWith('-----')) continue;
                if (!parsing) continue;
                if (!line.trim()) continue;
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 4) {
                    entries.push({ name: parts.slice(3).join(" "), size: parts[0], date: `${parts[1]} ${parts[2]}` });
                }
            }
        } else if (parser === '7z') {
            // 7-Zip listing parser
            let parsing = false;
            for (const line of lines) {
                // Header usually contains "Date      Time    Attr..."
                if (line.includes('Date') && line.includes('Time') && line.includes('Attr')) { parsing = true; continue; }
                if (line.startsWith('-----')) continue;
                if (!parsing) continue;
                if (!line.trim()) continue;

                // Typical line: 2024-01-01 12:00:00 ....A      12345      12345  Name.txt
                const parts = line.trim().split(/\s+/);
                // We expect at least Date, Time, Attr, Size, Compressed, Name (6 parts)
                if (parts.length >= 6) {
                    const size = parts[3];
                    const name = parts.slice(5).join(" ");
                    entries.push({ name: name, size: size, date: `${parts[0]} ${parts[1]}` });
                } else if (parts.length >= 5) {
                    // Sometimes compressed size is missing or different format
                    const name = parts.slice(5).join(" ") || parts.slice(4).join(" "); // Fallback
                    entries.push({ name: name, size: "?", date: `${parts[0]} ${parts[1]}` });
                }
            }
        } else {
            // Generic/Raw parser (tar, etc)
            entries.push({ name: "Сырой вывод:", size: "", date: "" });
            for (const line of lines) {
                if (line.trim()) entries.push({ name: line.trim(), size: "", date: "" });
            }
        }

        res.status(200).json({ entries });
    });
});

// === AI CHAT ENDPOINT ===

app.post('/api/chat', authenticateToken, async (req, res) => {
    const { message, history } = req.body;
    const userEmail = req.user.email;
    const userName = req.user.name;

    if (!OPENAI_API_KEY) return res.status(500).json({ error: 'API ключ OpenAI не настроен' });

    // Define Tools
    const tools = [
        {
            type: "function",
            function: {
                name: "get_file_list",
                description: "Get a list of all files in the user's directory",
                parameters: { type: "object", properties: { path: { type: "string", description: "Sub-folder path (optional)" } } }
            }
        },
        {
            type: "function",
            function: {
                name: "read_file",
                description: "Read the content of a specific file. Only text files.",
                parameters: { type: "object", properties: { filename: { type: "string" } }, required: ["filename"] }
            }
        }
    ];

    // Prepare Messages
    const conversation = [
        {
            role: "system",
            content: `You are GlassDrive AI, a helpful AI assistant for the user's private cloud drive.
            User: ${userName} (${userEmail}).
            You have access to file tools. Use them when asked about files.
            Be concise and helpful. Always answer in Russian language.`
        },
        ...(history || []),
        { role: "user", content: message }
    ];

    // Tool Execution Loop
    let iterations = 0;
    const MAX_ITERATIONS = 5;

    try {
        while (iterations < MAX_ITERATIONS) {
            iterations++;

            const response = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${OPENAI_API_KEY}`
                },
                body: JSON.stringify({
                    model: "gpt-4o",
                    messages: conversation,
                    tools: tools,
                    tool_choice: "auto"
                })
            });

            if (!response.ok) {
                const err = await response.text();
                throw new Error(`OpenAI API Error: ${err}`);
            }

            const data = await response.json();
            const choice = data.choices[0];
            const msg = choice.message;

            // Add assistant message to conversation
            conversation.push(msg);

            // Check for Tool Calls
            if (msg.tool_calls) {
                for (const toolCall of msg.tool_calls) {
                    const fnName = toolCall.function.name;
                    const args = JSON.parse(toolCall.function.arguments);
                    let result = "";

                    // Execute Tool Safely
                    try {
                        const safeName = sanitizeName(userEmail);
                        const userFilesRoot = path.join(STORAGE_DIR, safeName, 'files');

                        if (fnName === "get_file_list") {
                            const subDir = args.path || "";
                            const targetPath = path.join(userFilesRoot, subDir.replace(/\.\./g, ''));
                            if (fs.existsSync(targetPath)) {
                                const files = fs.readdirSync(targetPath);
                                result = JSON.stringify(files);
                            } else {
                                result = "Directory not found";
                            }
                        } else if (fnName === "read_file") {
                            const fPath = args.filename.replace(/\.\./g, '');
                            const targetPath = path.join(userFilesRoot, fPath);
                            if (fs.existsSync(targetPath)) {
                                const stats = fs.statSync(targetPath);
                                if (stats.size > 100000) {
                                    result = "File too large to read";
                                } else {
                                    result = fs.readFileSync(targetPath, 'utf8');
                                }
                            } else {
                                result = "File not found";
                            }
                        } else {
                            result = "Unknown tool";
                        }
                    } catch (e) {
                        result = `Error executing tool: ${e.message}`;
                    }

                    // Add Tool Output
                    conversation.push({
                        role: "tool",
                        tool_call_id: toolCall.id,
                        content: result
                    });
                }
                // Loop continues
            } else {
                // Final answer
                return res.json({ reply: msg.content });
            }
        }
    } catch (e) {
        console.error("Chat Loop Error:", e);
        return res.status(500).json({ error: "Не удалось обработать запрос чата" });
    }

    return res.json({ reply: "Я думаю... но шаги закончились." });
});

app.get('/api/check-auth', (req, res) => {
    // если пока нет авторизации
    res.json({
        authenticated: false
    });
});

res.cookie('auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
});
res.json({ success: true });


// Start Server
app.listen(PORT, () => {
    console.log(`Secure Server running on port ${PORT}`);
    console.log(`Storage: ${STORAGE_DIR}`);
});
