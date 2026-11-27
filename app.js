// --- 1. CONFIGURACIÓN DE SUPABASE AUTH Y SEGURIDAD ---
        const SUPABASE_URL = 'https://ywvndnoxnlnwbkrligwi.supabase.co';
        const SUPABASE_ANON_KEY = 'sb_publishable_vX4wOVRc7TLD_LHw7flFZg_cUdUQtZe';

        // Almacenamiento resiliente compatible con iframes sandbox y navegadores estrictos
        const safeAuthStorage = (() => {
            const memoryStore = {};
            return {
                getItem: (key) => {
                    try { return window.localStorage.getItem(key); } catch (e) { return memoryStore[key] ?? null; }
                },
                setItem: (key, value) => {
                    try { window.localStorage.setItem(key, value); } catch (e) { memoryStore[key] = String(value); }
                },
                removeItem: (key) => {
                    try { window.localStorage.removeItem(key); } catch (e) { delete memoryStore[key]; }
                }
            };
        })();

        // Cliente oficial de Supabase con gestión de sesión JWT real
        const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
            auth: {
                storage: safeAuthStorage,
                persistSession: true,
                autoRefreshToken: true,
                detectSessionInUrl: true
            }
        });

        // Catálogo de los 8 módulos oficiales de la tabla public.modules
        const SYSTEM_MODULES = [
            { key: 'students', label: 'Estudiantes' },
            { key: 'programs', label: 'Programas' },
            { key: 'assignments', label: 'Actividades' },
            { key: 'grades', label: 'Calificaciones' },
            { key: 'attendance', label: 'Asistencia' },
            { key: 'accounting', label: 'Contabilidad' },
            { key: 'docs', label: 'Documentos' },
            { key: 'chat_messages', label: 'Mensajería' }
        ];

        // Columnas permitidas al consultar usuarios (jamás incluye 'pass')
        const SAFE_USER_COLUMNS = 'id, auth_user_id, inst_id, role, name, last_name, document, doc_type, birth_date, lugar_nac, sexo, email, tel, cel, dir, lugar_res, barrio, periodo, sede, horario, avatar, is_online, perms';

        const security = {
            esc: (str) => {
                if (str === null || str === undefined) return '';
                return String(str)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            },

            escAttr: (str) => {
                return security.esc(str).replace(/`/g, '&#96;');
            },

            safeUrl: (url, fallback = '') => {
                if (!url || typeof url !== 'string') return fallback;
                const trimmed = url.trim();
                const isSafeHttps = trimmed.startsWith('https://');
                const isSafeRasterData = /^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/i.test(trimmed);
                if (isSafeHttps || isSafeRasterData) {
                    return security.escAttr(trimmed);
                }
                return fallback;
            },

            sanitizeUser: (user) => {
                if (!user) return user;
                const clean = { ...user };
                delete clean.pass;
                return clean;
            },

            validateStrongPassword: (pwd) => {
                if (!pwd || pwd.length < 8) {
                    return 'La contraseña debe tener al menos 8 caracteres.';
                }
                if (!/[A-Za-z]/.test(pwd) || !/[0-9]/.test(pwd)) {
                    return 'La contraseña debe combinar letras y números.';
                }
                const weak = ['12345678', 'password', 'password1', 'qwerty123', 'admin123'];
                if (weak.includes(pwd.toLowerCase())) {
                    return 'La contraseña elegida es demasiado común. Elige una más segura.';
                }
                return null;
            },

            validateFile: (file, allowedTypes, maxBytes) => {
                if (!file) return 'No se seleccionó ningún archivo.';
                if (!allowedTypes.includes(file.type)) {
                    return 'Tipo de archivo no permitido.';
                }
                if (file.size > maxBytes) {
                    const mb = Math.round(maxBytes / (1024 * 1024));
                    return `El archivo supera el tamaño máximo permitido (${mb} MB).`;
                }
                return null;
            }
        };

        const sbMapper = {
            toDb: (table, item) => {
                switch (table) {
                    case 'institutions':
                        return { id: item.id, name: item.name, nit: item.nit, email: item.email || '', type: item.type || 'Técnica', status: item.status || 'Activo' };
                    case 'users':
                        return {
                            id: item.id, inst_id: item.instId || null, role: item.role, name: item.name, last_name: item.lastName || '',
                            document: item.document || '', doc_type: item.docType || '', birth_date: item.birthDate || '', lugar_nac: item.lugarNac || '',
                            sexo: item.sexo || '', email: item.email, tel: item.tel || '', cel: item.cel || '', dir: item.dir || '',
                            lugar_res: item.lugarRes || '', barrio: item.barrio || '', periodo: item.periodo || '', sede: item.sede || '',
                            horario: item.horario || '', avatar: item.avatar || null, is_online: !!item.isOnline
                        };
                    case 'programs':
                        return {
                            id: item.id, inst_id: item.instId || null, code: item.code || '', nombre: item.nombre, calendario: item.calendario || 'A',
                            anio: String(item['año'] || item.anio || new Date().getFullYear()), jornada: item.jornada || 'Mañana',
                            horarios: item.horarios || [], salones: item.salones || [], modulos: item.modulos || [],
                            cost_matricula: Number(item.costMatricula || 0), cost_mensualidad: Number(item.costMensualidad || 0),
                            duration_meses: Number(item.durationMeses || 1), cost_uniforme: Number(item.costUniforme || 0),
                            fecha_cierre: item.fechaCierre || ''
                        };
                    case 'assignments':
                        return { id: item.id, inst_id: item.instId || null, program_id: item.programId, salon: item.salon, teacher_id: item.teacherId || null, student_ids: item.studentIds || [] };
                    case 'grades':
                        return { id: item.id, inst_id: item.instId || auth.currentUser?.instId || null, program_id: item.programId, module_id: item.moduleId || null, module_name: item.moduleName || '', student_id: item.studentId, desc: item.desc, grade: String(item.grade) };
                    case 'attendance':
                        return { id: item.id, inst_id: item.instId || auth.currentUser?.instId || null, program_id: item.programId, salon: item.salon, date: item.date, teacher_id: item.teacherId || null, records: item.records || [] };
                    case 'accounting':
                        return { id: item.id, inst_id: item.instId || null, student_id: item.studentId || null, date: item.date, type: item.type, amount: Number(item.amount || 0), desc: item.desc, ref: item.ref || null };
                    case 'docs':
                        return { id: item.id, inst_id: item.instId || null, student_id: item.studentId, file_name: item.fileName, file_url: item.fileUrl || null, desc: item.desc, upload_date: item.uploadDate || '' };
                    case 'chat_messages':
                        return { id: item.id, from_id: item.fromId, to_id: item.toId, text: item.text, timestamp: Number(item.timestamp), read: !!item.read };
                    default:
                        return item;
                }
            },
            fromDb: (table, row) => {
                if (!row) return row;
                switch (table) {
                    case 'institutions':
                        return { id: row.id, name: row.name, nit: row.nit, email: row.email || '', type: row.type || 'Técnica', status: row.status || 'Activo' };
                    case 'users':
                        return {
                            id: row.id, authUserId: row.auth_user_id || null, instId: row.inst_id || null, role: row.role, name: row.name, lastName: row.last_name || '',
                            document: row.document || '', docType: row.doc_type || '', birthDate: row.birth_date || '', lugarNac: row.lugar_nac || '',
                            sexo: row.sexo || '', email: row.email, tel: row.tel || '', cel: row.cel || '', dir: row.dir || '',
                            lugarRes: row.lugar_res || '', barrio: row.barrio || '', periodo: row.periodo || '', sede: row.sede || '',
                            horario: row.horario || '', avatar: row.avatar || null, isOnline: !!row.is_online, perms: row.perms || null
                        };
                    case 'programs':
                        return {
                            id: row.id, instId: row.inst_id || null, code: row.code || '', nombre: row.nombre, calendario: row.calendario || 'A',
                            'año': row.anio || String(new Date().getFullYear()), jornada: row.jornada || 'Mañana',
                            horarios: row.horarios || [], salones: row.salones || [], modulos: row.modulos || [],
                            costMatricula: String(row.cost_matricula || 0), costMensualidad: String(row.cost_mensualidad || 0),
                            durationMeses: String(row.duration_meses || 1), costUniforme: String(row.cost_uniforme || 0),
                            fechaCierre: row.fecha_cierre || ''
                        };
                    case 'assignments':
                        return { id: row.id, instId: row.inst_id || null, programId: row.program_id, salon: row.salon, teacherId: row.teacher_id || null, studentIds: row.student_ids || [] };
                    case 'grades':
                        return { id: row.id, instId: row.inst_id || null, programId: row.program_id, moduleId: row.module_id || null, moduleName: row.module_name || '', studentId: row.student_id, desc: row.desc, grade: row.grade };
                    case 'attendance':
                        return { id: row.id, instId: row.inst_id || null, programId: row.program_id, salon: row.salon, date: row.date, teacherId: row.teacher_id || null, records: row.records || [] };
                    case 'accounting':
                        return { id: row.id, instId: row.inst_id || null, studentId: row.student_id || null, date: row.date, type: row.type, amount: Number(row.amount || 0), desc: row.desc, ref: row.ref || null };
                    case 'docs':
                        return { id: row.id, instId: row.inst_id || null, studentId: row.student_id, fileName: row.file_name, fileUrl: row.file_url || null, desc: row.desc, uploadDate: row.upload_date || '' };
                    case 'chat_messages':
                        return { id: row.id, fromId: row.from_id, toId: row.to_id, text: row.text, timestamp: Number(row.timestamp), read: !!row.read };
                    default:
                        return row;
                }
            }
        };

        // --- 2. CAPA DE DATOS CON FILTRADO POR PERMISOS Y RLS ---
        const db = {
            cache: {
                institutions: [], users: [], programs: [], assignments: [],
                grades: [], attendance: [], accounting: [], docs: [], chat_messages: [],
                coordinator_permissions: [], globalStats: null
            },
            ready: false,
            realtimeChannel: null,
            pollingTimer: null,

            init: async function() {
                this.ready = true;
            },

            buildScopedQuery: function(table) {
                const me = auth.currentUser;
                const cols = table === 'users' ? SAFE_USER_COLUMNS : '*';
                let q = supabaseClient.from(table).select(cols);

                if (!me) return q.limit(0);

                if (me.role === 'admin') {
                    if (table === 'institutions') return q;
                    if (table === 'users') return q.in('role', ['admin', 'rector']);
                    if (table === 'chat_messages') return q.or(`from_id.eq.${me.id},to_id.eq.${me.id}`);
                    return q.limit(0);
                }

                const instId = me.instId;
                switch (table) {
                    case 'institutions':
                        return instId ? q.eq('id', instId) : q.limit(0);
                    case 'users':
                        if (me.role === 'estudiante') return q.eq('id', me.id);
                        return instId ? q.eq('inst_id', instId) : q.limit(0);
                    case 'coordinator_permissions':
                        if (me.role === 'rector') return q.eq('institution_id', instId);
                        if (me.role === 'coordinador') return q.eq('coordinator_user_id', me.id);
                        return q.limit(0);
                    case 'programs':
                    case 'assignments':
                    case 'accounting':
                    case 'docs':
                        if (me.role === 'estudiante') {
                            if (table === 'accounting' || table === 'docs') return q.eq('student_id', me.id);
                            return instId ? q.eq('inst_id', instId) : q.limit(0);
                        }
                        if (me.role === 'profesor' && (table === 'accounting' || table === 'docs')) {
                            return q.limit(0);
                        }
                        return instId ? q.eq('inst_id', instId) : q.limit(0);
                    case 'grades':
                        if (me.role === 'estudiante') return q.eq('student_id', me.id);
                        return instId ? q.eq('inst_id', instId) : q.limit(0);
                    case 'attendance':
                        if (me.role === 'estudiante') return q.limit(0);
                        if (me.role === 'profesor') return q.eq('teacher_id', me.id);
                        return instId ? q.eq('inst_id', instId) : q.limit(0);
                    case 'chat_messages':
                        if (me.role === 'estudiante') return q.limit(0);
                        return q.or(`from_id.eq.${me.id},to_id.eq.${me.id}`);
                    default:
                        return q.limit(0);
                }
            },

            getAuthorizedTables: function() {
                const me = auth.currentUser;
                if (!me) return [];
                if (me.role === 'admin') return ['institutions', 'users', 'chat_messages'];
                if (me.role === 'estudiante') return ['institutions', 'users', 'programs', 'assignments', 'grades', 'accounting', 'docs'];
                if (me.role === 'profesor') return ['institutions', 'users', 'programs', 'assignments', 'grades', 'attendance', 'chat_messages'];
                if (me.role === 'rector') return ['institutions', 'users', 'coordinator_permissions', 'programs', 'assignments', 'grades', 'attendance', 'accounting', 'docs', 'chat_messages'];

                const tables = ['institutions', 'users', 'coordinator_permissions'];
                if (auth.can('programs', 'view')) tables.push('programs');
                if (auth.can('assignments', 'view')) tables.push('assignments');
                if (auth.can('grades', 'view')) tables.push('grades');
                if (auth.can('attendance', 'view')) tables.push('attendance');
                if (auth.can('accounting', 'view')) tables.push('accounting');
                if (auth.can('docs', 'view')) tables.push('docs');
                if (auth.can('chat_messages', 'view')) tables.push('chat_messages');
                return tables;
            },

            loadAuthenticatedData: async function() {
                const tables = this.getAuthorizedTables();
                try {
                    await Promise.all(tables.map(async (t) => {
                        const { data, error } = await this.buildScopedQuery(t);
                        if (!error && data) {
                            this.cache[t] = t === 'coordinator_permissions' ? data : data.map(r => sbMapper.fromDb(t, r));
                        }
                    }));

                    // Firmar dinámicamente las rutas privadas de avatares para que nunca caduquen en sesión
                    await Promise.all((this.cache.users || []).map(async (u) => {
                        if (u.avatar && !u.avatar.startsWith('https://') && !u.avatar.startsWith('data:')) {
                            const signed = await this.getSignedFileUrl(u.avatar, 3600);
                            if (signed) u.avatar = signed;
                        }
                    }));

                    if (auth.currentUser && auth.currentUser.avatar && !auth.currentUser.avatar.startsWith('https://') && !auth.currentUser.avatar.startsWith('data:')) {
                        const signedMe = await this.getSignedFileUrl(auth.currentUser.avatar, 3600);
                        if (signedMe) auth.currentUser.avatar = signedMe;
                    }

                    if (auth.currentUser?.role === 'admin') {
                        const { data: statsData } = await supabaseClient.rpc('get_global_stats');
                        if (statsData) this.cache.globalStats = statsData;
                    }

                    this.ready = true;
                    this.subscribeRealtime();
                } catch (err) {
                    console.error('[Supabase] Error cargando datos autorizados:', err);
                    this.ready = true;
                }
            },

            refreshTable: async function(table) {
                if (!auth.currentUser) return;
                if (!this.getAuthorizedTables().includes(table)) return;
                try {
                    const { data, error } = await this.buildScopedQuery(table);
                    if (!error && data) {
                        this.cache[table] = table === 'coordinator_permissions' ? data : data.map(r => sbMapper.fromDb(table, r));
                    }
                } catch (e) {}
            },

            get: function(key) {
                return [...(this.cache[key] || [])];
            },

            insertRecord: async function(table, item) {
                const mapped = sbMapper.toDb(table, item);
                const selectCols = table === 'users' ? SAFE_USER_COLUMNS : '*';
                const { data, error } = await supabaseClient.from(table).insert([mapped]).select(selectCols);
                if (error) {
                    console.error(`[Supabase Insert ${table}]`, error.message);
                    ui.showModal('Operación Rechazada por el Servidor', error.message);
                    return false;
                }
                const saved = data && data[0] ? security.sanitizeUser(sbMapper.fromDb(table, data[0])) : security.sanitizeUser(item);
                this.cache[table].push(saved);
                return true;
            },

            updateRecord: async function(table, item) {
                const mapped = sbMapper.toDb(table, item);
                const recordId = mapped.id;
                delete mapped.id;
                if (table === 'chat_messages') {
                    // Al actualizar mensajes recibidos solo se permite marcar como leído
                    const { data, error } = await supabaseClient.from(table).update({ read: !!item.read }).eq('id', recordId).select('*');
                    if (error) {
                        console.error(`[Supabase Update ${table}]`, error.message);
                        return false;
                    }
                    const saved = data && data[0] ? sbMapper.fromDb(table, data[0]) : item;
                    const idx = this.cache[table].findIndex(x => String(x.id) === String(saved.id));
                    if (idx > -1) this.cache[table][idx] = saved;
                    return true;
                }

                const selectCols = table === 'users' ? SAFE_USER_COLUMNS : '*';
                const { data, error } = await supabaseClient.from(table).update(mapped).eq('id', recordId).select(selectCols);
                if (error) {
                    console.error(`[Supabase Update ${table}]`, error.message);
                    ui.showModal('Actualización Rechazada por el Servidor', error.message);
                    return false;
                }
                const saved = data && data[0] ? security.sanitizeUser(sbMapper.fromDb(table, data[0])) : security.sanitizeUser(item);
                const idx = this.cache[table].findIndex(x => String(x.id) === String(saved.id));
                if (idx > -1) this.cache[table][idx] = saved;
                return true;
            },

            deleteRecord: async function(table, id) {
                const { error } = await supabaseClient.from(table).delete().eq('id', id);
                if (error) {
                    console.error(`[Supabase Delete ${table}]`, error.message);
                    ui.showModal('Eliminación Rechazada por el Servidor', error.message);
                    return false;
                }
                this.cache[table] = this.cache[table].filter(x => String(x.id) !== String(id));
                return true;
            },

            set: async function(key, newArray) {
                const oldArray = this.cache[key] || [];
                const newIds = new Set(newArray.map(item => String(item.id)));
                const deletedIds = oldArray.filter(item => !newIds.has(String(item.id))).map(item => item.id);

                for (const delId of deletedIds) {
                    const ok = await this.deleteRecord(key, delId);
                    if (!ok) return false;
                }

                for (const item of newArray) {
                    const prev = oldArray.find(o => String(o.id) === String(item.id));
                    if (!prev) {
                        const ok = await this.insertRecord(key, item);
                        if (!ok) return false;
                    } else if (JSON.stringify(prev) !== JSON.stringify(item)) {
                        const ok = await this.updateRecord(key, item);
                        if (!ok) return false;
                    }
                }
                return true;
            },

            uploadPrivateFile: async function(folder, file) {
                const ext = (file.name.split('.').pop() || '').toLowerCase().replace(/[^a-z0-9]/g, '');
                const randomId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
                const path = `${folder}/${randomId}${ext ? '.' + ext : ''}`;
                const { error } = await supabaseClient.storage.from('integra-files').upload(path, file, {
                    upsert: false,
                    contentType: file.type
                });
                if (error) {
                    console.warn('[Supabase Storage]', error.message);
                    ui.showModal('Error de Almacenamiento', `No se pudo subir el archivo privado: ${error.message}`);
                    return null;
                }
                return path;
            },

            getSignedFileUrl: async function(storagePath, expiresSeconds = 120) {
                if (!storagePath) return null;
                if (storagePath.startsWith('https://')) return storagePath;
                const { data, error } = await supabaseClient.storage.from('integra-files').createSignedUrl(storagePath, expiresSeconds);
                if (error || !data?.signedUrl) {
                    ui.showModal('Acceso Denegado al Documento', 'No fue posible generar el enlace temporal firmado o no tienes permisos.');
                    return null;
                }
                return data.signedUrl;
            },

            startHttpSync: function() {
                if (this.pollingTimer) return;
                this.pollingTimer = setInterval(async () => {
                    if (!auth.currentUser || !chat.isAllowedRole()) return;
                    await Promise.all([
                        this.refreshTable('users'),
                        this.refreshTable('chat_messages')
                    ]);
                    chat.refreshUI();
                }, 4000);
            },

            subscribeRealtime: function() {
                if (this.realtimeChannel) return;
                this.startHttpSync();

                let wsAllowed = false;
                try {
                    if (typeof window.WebSocket === 'function' && window.self === window.top) {
                        wsAllowed = true;
                    }
                } catch (e) {
                    wsAllowed = false;
                }
                if (!wsAllowed) return;

                try {
                    const me = auth.currentUser;
                    if (!me || !chat.isAllowedRole()) return;

                    this.realtimeChannel = supabaseClient
                        .channel(`integra-rt-${me.id}`)
                        .on('postgres_changes', {
                            event: '*',
                            schema: 'public',
                            table: 'chat_messages',
                            filter: `to_id=eq.${me.id}`
                        }, async () => {
                            await this.refreshTable('chat_messages');
                            chat.refreshUI();
                        })
                        .on('postgres_changes', {
                            event: 'UPDATE',
                            schema: 'public',
                            table: 'users'
                        }, async () => {
                            await this.refreshTable('users');
                            chat.refreshUI();
                        })
                        .subscribe((status) => {
                            if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
                                this.startHttpSync();
                            }
                        });
                } catch (err) {
                    this.startHttpSync();
                }
            }
        };

        // --- 3. AUTENTICACIÓN NATIVA CON SUPABASE AUTH ---
        const auth = {
            currentUser: null,
            currentInstitution: null,
            modulePermissions: [],

            can: function(moduleKey, action = 'view') {
                const u = this.currentUser;
                if (!u) return false;
                if (u.role === 'admin') {
                    return moduleKey === 'chat_messages';
                }
                if (u.role === 'rector') {
                    return true;
                }
                if (u.role === 'coordinador') {
                    const found = (this.modulePermissions || []).find(p => p.module_key === moduleKey);
                    if (!found) return false;
                    const map = { view: 'can_view', create: 'can_create', update: 'can_update', delete: 'can_delete' };
                    return !!found[map[action]];
                }
                if (u.role === 'profesor') {
                    return ['programs', 'assignments', 'grades', 'attendance', 'chat_messages'].includes(moduleKey);
                }
                if (u.role === 'estudiante') {
                    return action === 'view' && ['programs', 'assignments', 'grades', 'accounting', 'docs'].includes(moduleKey);
                }
                return false;
            },

            setOnlineStatus: function(userId, status) {
                if (!userId) return;
                const users = db.cache.users;
                const idx = users.findIndex(u => u.id === userId);
                if (idx > -1) users[idx].isOnline = status;
                supabaseClient.rpc('set_my_online_status', { p_is_online: status }).then(() => {});
            },

            hydrateFromServerContext: async function() {
                const { data: ctx, error } = await supabaseClient.rpc('get_my_integra_context');
                if (error || !ctx || !ctx.user) {
                    return false;
                }

                this.currentUser = security.sanitizeUser(sbMapper.fromDb('users', ctx.user));
                this.currentInstitution = ctx.institution ? sbMapper.fromDb('institutions', ctx.institution) : null;
                this.modulePermissions = Array.isArray(ctx.module_permissions) ? ctx.module_permissions : [];

                await db.loadAuthenticatedData();
                this.setOnlineStatus(this.currentUser.id, true);
                return true;
            },

            login: async function(e) {
                e.preventDefault();
                const identifier = document.getElementById('login-email').value.trim();
                const pass = document.getElementById('login-pass').value;
                const submitBtn = e.target.querySelector('button[type="submit"]');
                const origBtnHtml = submitBtn ? submitBtn.innerHTML : '';

                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<span>Autenticando...</span>';
                }

                try {
                    const { data: resolvedEmail, error: resErr } = await supabaseClient.rpc('resolve_login_email', {
                        p_identifier: identifier
                    });

                    if (resErr) {
                        return ui.showModal('Acceso Bloqueado', resErr.message);
                    }

                    const { data: authData, error: signErr } = await supabaseClient.auth.signInWithPassword({
                        email: resolvedEmail,
                        password: pass
                    });

                    if (signErr || !authData?.session) {
                        try { await supabaseClient.rpc('record_login_result', { p_identifier: identifier, p_success: false }); } catch (e) {}
                        return ui.showModal('Acceso Denegado', 'Credenciales inválidas o cuenta no activada.');
                    }

                    try { await supabaseClient.rpc('record_login_result', { p_identifier: identifier, p_success: true }); } catch (e) {}
                    document.getElementById('login-pass').value = '';

                    const ok = await this.hydrateFromServerContext();
                    if (!ok) {
                        await supabaseClient.auth.signOut();
                        return ui.showModal('Perfil No Vinculado', 'Tu cuenta de autenticación no tiene un perfil activo en INTEGRA LMS.');
                    }

                    ui.showApp();
                } finally {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = origBtnHtml;
                    }
                }
            },

            logout: async function() {
                if (this.currentUser) {
                    try { await supabaseClient.rpc('set_my_online_status', { p_is_online: false }); } catch (e) {}
                }
                await supabaseClient.auth.signOut().catch(() => {});
                this.currentUser = null;
                this.currentInstitution = null;
                this.modulePermissions = [];

                if (db.pollingTimer) {
                    clearInterval(db.pollingTimer);
                    db.pollingTimer = null;
                }
                if (db.realtimeChannel) {
                    supabaseClient.removeChannel(db.realtimeChannel);
                    db.realtimeChannel = null;
                }

                db.cache = {
                    institutions: [], users: [], programs: [], assignments: [],
                    grades: [], attendance: [], accounting: [], docs: [], chat_messages: [],
                    coordinator_permissions: [], globalStats: null
                };
                chat.openWindows = [];
                chat.rosterOpen = false;
                document.getElementById('chat-windows-dock').innerHTML = '';
                try {
                    sessionStorage.removeItem('integra_session');
                    sessionStorage.removeItem('integra_session_token');
                } catch (e) {}
                ui.showLogin();
            },

            checkSession: async function() {
                try {
                    sessionStorage.removeItem('integra_session');
                    sessionStorage.removeItem('integra_session_token');
                } catch (e) {}

                const hash = window.location.hash || '';
                if (hash.includes('type=recovery')) {
                    this.openTokenResetModal(true);
                    return;
                }

                const { data: { session } } = await supabaseClient.auth.getSession();
                if (!session) return;

                const ok = await this.hydrateFromServerContext();
                if (ok) {
                    ui.showApp();
                } else {
                    await supabaseClient.auth.signOut();
                }
            },

            openTokenResetModal: (isRecoveryMode = false) => {
                const reqForm = document.getElementById('recovery-request-form');
                const updForm = document.getElementById('recovery-update-form');
                const title = document.getElementById('recovery-modal-title');
                if (isRecoveryMode) {
                    title.innerText = 'Establecer Nueva Contraseña';
                    reqForm.classList.add('hidden');
                    updForm.classList.remove('hidden');
                } else {
                    title.innerText = 'Recuperar / Activar Acceso';
                    updForm.classList.add('hidden');
                    reqForm.classList.remove('hidden');
                    document.getElementById('reset-identifier').value = '';
                }
                document.getElementById('token-reset-modal').classList.remove('hidden');
            },

            closeTokenResetModal: () => {
                document.getElementById('token-reset-modal').classList.add('hidden');
            },

            requestPasswordRecovery: async (e) => {
                e.preventDefault();
                const identifier = document.getElementById('reset-identifier').value.trim();
                const { data: email, error: resErr } = await supabaseClient.rpc('resolve_login_email', {
                    p_identifier: identifier
                });
                if (resErr) {
                    return ui.showModal('Aviso', resErr.message);
                }

                await supabaseClient.auth.resetPasswordForEmail(email, {
                    redirectTo: window.location.origin + window.location.pathname
                });

                auth.closeTokenResetModal();
                ui.showModal('Solicitud Procesada', 'Si el correo o documento está registrado en la plataforma, recibirás un enlace seguro para restablecer tu contraseña.');
            },

            completePasswordRecovery: async (e) => {
                e.preventDefault();
                const newPass = document.getElementById('reset-new-pass').value;
                const confirmPass = document.getElementById('reset-confirm-pass').value;

                if (newPass !== confirmPass) {
                    return ui.showModal('Error', 'La confirmación de contraseña no coincide.');
                }
                const strengthErr = security.validateStrongPassword(newPass);
                if (strengthErr) {
                    return ui.showModal('Contraseña Débil', strengthErr);
                }

                const { error } = await supabaseClient.auth.updateUser({ password: newPass });
                if (error) {
                    return ui.showModal('Error', error.message);
                }

                try { window.history.replaceState(null, '', window.location.pathname); } catch (e) {}
                auth.closeTokenResetModal();
                const ok = await auth.hydrateFromServerContext();
                if (ok) {
                    ui.showApp();
                }
                ui.showModal('Contraseña Actualizada', 'Tu nueva contraseña ha sido guardada en Supabase Auth.');
            }
        };

        supabaseClient.auth.onAuthStateChange((event) => {
            if (event === 'PASSWORD_RECOVERY') {
                auth.openTokenResetModal(true);
            } else if (event === 'SIGNED_OUT' && auth.currentUser) {
                auth.currentUser = null;
                ui.showLogin();
            }
        });

        // --- 4. CHAT EN LÍNEA INDEPENDIENTE ---
        const chat = {
            rosterOpen: false,
            openWindows: [],
            RETENTION_MS: 30 * 24 * 60 * 60 * 1000,

            isAllowedRole: () => {
                if (!auth.currentUser) return false;
                if (!['admin', 'rector', 'coordinador', 'profesor'].includes(auth.currentUser.role)) return false;
                return auth.can('chat_messages', 'view');
            },

            pruneOldMessages: () => {
                const now = Date.now();
                const msgs = db.get('chat_messages');
                const valid = msgs.filter(m => (now - m.timestamp) <= chat.RETENTION_MS);
                if (valid.length !== msgs.length) {
                    db.set('chat_messages', valid);
                }
                return valid;
            },

            getContacts: () => {
                if (!chat.isAllowedRole()) return [];
                const me = auth.currentUser;
                const allUsers = db.get('users').filter(u => u.id !== me.id && ['admin', 'rector', 'coordinador', 'profesor'].includes(u.role));

                if (me.role === 'admin') {
                    return allUsers.filter(u => u.role === 'rector' || u.role === 'admin');
                }
                return allUsers.filter(u => u.role === 'admin' || u.instId === me.instId);
            },

            getRoleLabel: (user) => {
                const map = { admin: 'Super Admin', rector: 'Rectoría', coordinador: 'Coordinación', profesor: 'Docente' };
                const base = map[user.role] || user.role;
                if (user.instId && auth.currentUser && auth.currentUser.role === 'admin') {
                    const inst = db.get('institutions').find(i => i.id === user.instId);
                    return inst ? `${base} · ${inst.name}` : base;
                }
                return base;
            },

            toggleRoster: (e) => {
                if (e) e.stopPropagation();
                chat.rosterOpen = !chat.rosterOpen;
                const dd = document.getElementById('chat-roster-dropdown');
                if (chat.rosterOpen) {
                    dd.classList.remove('hidden');
                    chat.renderRoster();
                    const inp = document.getElementById('chat-search-input');
                    if (inp) setTimeout(() => inp.focus(), 50);
                } else {
                    dd.classList.add('hidden');
                }
            },

            closeRoster: () => {
                chat.rosterOpen = false;
                const dd = document.getElementById('chat-roster-dropdown');
                if (dd) dd.classList.add('hidden');
            },

            refreshUI: () => {
                const widget = document.getElementById('chat-header-widget');
                if (!widget) return;

                if (!chat.isAllowedRole()) {
                    widget.classList.add('hidden');
                    document.getElementById('chat-windows-dock').innerHTML = '';
                    return;
                }

                widget.classList.remove('hidden');
                const msgs = chat.pruneOldMessages();
                const contacts = chat.getContacts();
                const onlineContacts = contacts.filter(c => c.isOnline === true);
                const meId = auth.currentUser.id;

                const countLabel = document.getElementById('chat-online-count-label');
                const subtitle = document.getElementById('chat-panel-subtitle');
                const avatarsBox = document.getElementById('chat-header-avatars');

                countLabel.innerText = `${onlineContacts.length} conectado${onlineContacts.length === 1 ? '' : 's'}`;
                if (subtitle) subtitle.innerText = `${onlineContacts.length} conectado${onlineContacts.length === 1 ? '' : 's'} ahora`;

                if (onlineContacts.length === 0) {
                    avatarsBox.innerHTML = `<span class="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs"><i class="ph-fill ph-chats-circle"></i></span>`;
                } else {
                    avatarsBox.innerHTML = onlineContacts.slice(0, 3).map((c, i) => {
                        const bgColors = ['bg-emerald-500', 'bg-amber-500', 'bg-teal-500'];
                        const initial = security.esc((c.name || '?').charAt(0).toUpperCase());
                        return c.avatar
                            ? `<img src="${security.safeUrl(c.avatar)}" class="w-6 h-6 rounded-full object-cover ring-2 ring-slate-900">`
                            : `<span class="w-6 h-6 rounded-full ${bgColors[i % bgColors.length]} text-slate-950 text-[10px] font-extrabold flex items-center justify-center ring-2 ring-slate-900">${initial}</span>`;
                    }).join('');
                }

                const unreadTotal = msgs.filter(m => m.toId === meId && !m.read).length;
                const badge = document.getElementById('chat-unread-badge');
                if (unreadTotal > 0) {
                    badge.innerText = unreadTotal > 99 ? '99+' : unreadTotal;
                    badge.classList.remove('hidden');
                } else {
                    badge.classList.add('hidden');
                }

                if (chat.rosterOpen) chat.renderRoster();
                chat.renderWindows();
            },

            renderRoster: () => {
                const listEl = document.getElementById('chat-roster-list');
                if (!listEl) return;

                const query = (document.getElementById('chat-search-input')?.value || '').toLowerCase().trim();
                const msgs = db.get('chat_messages');
                const meId = auth.currentUser.id;
                let contacts = chat.getContacts();

                if (query) {
                    contacts = contacts.filter(c =>
                        (c.name || '').toLowerCase().includes(query) ||
                        (c.role || '').toLowerCase().includes(query)
                    );
                }

                const online = contacts.filter(c => c.isOnline === true);
                const offline = contacts.filter(c => !c.isOnline);

                const renderPersonRow = (person, isOnline) => {
                    const unread = msgs.filter(m => m.fromId === person.id && m.toId === meId && !m.read).length;
                    const safeName = security.esc(person.name);
                    const safeRole = security.esc(chat.getRoleLabel(person));
                    const initial = security.esc((person.name || '?').charAt(0).toUpperCase());
                    const avatarHtml = person.avatar
                        ? `<img src="${security.safeUrl(person.avatar)}" class="w-10 h-10 rounded-full object-cover border border-slate-200">`
                        : `<div class="w-10 h-10 rounded-full ${isOnline ? 'bg-emerald-600 text-white' : 'bg-slate-600 text-white'} font-bold text-sm flex items-center justify-center">${initial}</div>`;

                    return `
                        <div onclick="chat.openChat(${person.id})" class="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50 cursor-pointer transition">
                            <div class="flex items-center gap-3 min-w-0">
                                <div class="relative flex-shrink-0">
                                    ${avatarHtml}
                                    <span class="absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-white ${isOnline ? 'bg-emerald-500 online-pulse' : 'bg-slate-400'}"></span>
                                </div>
                                <div class="min-w-0">
                                    <p class="text-sm font-semibold text-slate-800 truncate leading-tight">${safeName}</p>
                                    <p class="text-xs text-slate-500 truncate mt-0.5">${safeRole}</p>
                                </div>
                            </div>
                            ${unread > 0 ? `<span class="ml-2 bg-amber-500 text-slate-950 text-[10px] font-extrabold px-2 py-0.5 rounded-full flex-shrink-0">${unread}</span>` : ''}
                        </div>
                    `;
                };

                if (contacts.length === 0) {
                    listEl.innerHTML = `<div class="p-6 text-center text-xs text-slate-400">No hay usuarios disponibles para chatear.</div>`;
                    return;
                }

                let html = '';
                html += `<div class="px-4 py-2 bg-slate-50 text-[11px] font-bold text-emerald-700 tracking-wider uppercase">Conectados ahora · ${online.length}</div>`;
                if (online.length === 0) {
                    html += `<div class="px-4 py-3 text-xs text-slate-400 italic">Nadie más conectado en este momento</div>`;
                } else {
                    html += online.map(p => renderPersonRow(p, true)).join('');
                }

                html += `<div class="px-4 py-2 bg-slate-50 text-[11px] font-bold text-slate-400 tracking-wider uppercase border-t border-slate-100">Desconectados · ${offline.length}</div>`;
                if (offline.length === 0) {
                    html += `<div class="px-4 py-3 text-xs text-slate-400 italic">Todos están conectados</div>`;
                } else {
                    html += offline.map(p => renderPersonRow(p, false)).join('');
                }

                listEl.innerHTML = html;
            },

            openChat: (userId) => {
                chat.closeRoster();
                const existing = chat.openWindows.find(w => w.userId === userId);
                if (existing) {
                    existing.minimized = false;
                } else {
                    if (chat.openWindows.length >= 3) chat.openWindows.shift();
                    chat.openWindows.push({ userId, minimized: false });
                }
                chat.markAsRead(userId);
                chat.renderWindows();
                setTimeout(() => {
                    const input = document.getElementById(`chat-input-${userId}`);
                    if (input) input.focus();
                }, 60);
            },

            closeChat: (userId, e) => {
                if (e) e.stopPropagation();
                chat.openWindows = chat.openWindows.filter(w => w.userId !== userId);
                chat.renderWindows();
            },

            toggleMinimize: (userId) => {
                const win = chat.openWindows.find(w => w.userId === userId);
                if (win) {
                    win.minimized = !win.minimized;
                    if (!win.minimized) chat.markAsRead(userId);
                    chat.renderWindows();
                }
            },

            markAsRead: (fromUserId) => {
                if (!auth.currentUser) return;
                const meId = auth.currentUser.id;
                const msgs = db.get('chat_messages');
                let changed = false;
                msgs.forEach(m => {
                    if (m.fromId === fromUserId && m.toId === meId && !m.read) {
                        m.read = true;
                        changed = true;
                    }
                });
                if (changed) {
                    db.set('chat_messages', msgs);
                    chat.refreshUI();
                }
            },

            sendMessage: (toUserId) => {
                const input = document.getElementById(`chat-input-${toUserId}`);
                if (!input) return;
                const text = input.value.trim();
                if (!text || !auth.currentUser) return;

                const msgs = chat.pruneOldMessages();
                msgs.push({
                    id: Date.now() + Math.floor(Math.random() * 1000),
                    fromId: auth.currentUser.id,
                    toId: toUserId,
                    text: text,
                    timestamp: Date.now(),
                    read: false
                });
                db.set('chat_messages', msgs);
                input.value = '';
                chat.renderWindows(true);
            },

            renderWindows: (forceScrollBottom = false) => {
                const dock = document.getElementById('chat-windows-dock');
                if (!dock || !auth.currentUser) return;

                if (chat.openWindows.length === 0) {
                    dock.innerHTML = '';
                    return;
                }

                const meId = auth.currentUser.id;
                const allUsers = db.get('users');
                const allMsgs = db.get('chat_messages');

                const savedDrafts = {};
                const prevScrolls = {};
                chat.openWindows.forEach(w => {
                    const inp = document.getElementById(`chat-input-${w.userId}`);
                    if (inp) savedDrafts[w.userId] = inp.value;
                    const body = document.getElementById(`chat-body-${w.userId}`);
                    if (body) prevScrolls[w.userId] = { top: body.scrollTop, height: body.scrollHeight, client: body.clientHeight };
                });

                let html = '';
                chat.openWindows.forEach(win => {
                    const peer = allUsers.find(u => u.id === win.userId);
                    if (!peer) return;

                    const isOnline = peer.isOnline === true;
                    const safePeerName = security.esc(peer.name);
                    const safePeerRole = security.esc(chat.getRoleLabel(peer));
                    const initial = security.esc((peer.name || '?').charAt(0).toUpperCase());
                    const convMsgs = allMsgs
                        .filter(m => (m.fromId === meId && m.toId === peer.id) || (m.fromId === peer.id && m.toId === meId))
                        .sort((a, b) => a.timestamp - b.timestamp);

                    const unreadCount = convMsgs.filter(m => m.fromId === peer.id && !m.read).length;

                    if (!win.minimized && unreadCount > 0) {
                        setTimeout(() => chat.markAsRead(peer.id), 100);
                    }

                    const avatarHtml = peer.avatar
                        ? `<img src="${security.safeUrl(peer.avatar)}" class="w-8 h-8 rounded-full object-cover border border-white/30">`
                        : `<div class="w-8 h-8 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs flex items-center justify-center">${initial}</div>`;

                    html += `
                        <div class="pointer-events-auto w-80 bg-white rounded-t-2xl shadow-2xl border border-slate-200 border-b-0 flex flex-col overflow-hidden">
                            <div onclick="chat.toggleMinimize(${peer.id})" class="bg-slate-900 hover:bg-slate-800 text-white px-3.5 py-2.5 flex items-center justify-between cursor-pointer select-none transition border-b border-emerald-500/30">
                                <div class="flex items-center gap-2.5 min-w-0">
                                    <div class="relative flex-shrink-0">
                                        ${avatarHtml}
                                        <span class="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full border-2 border-slate-900 ${isOnline ? 'bg-emerald-400' : 'bg-slate-400'}"></span>
                                    </div>
                                    <div class="min-w-0">
                                        <p class="text-xs font-bold truncate leading-tight">${safePeerName}</p>
                                        <p class="text-[10px] ${isOnline ? 'text-emerald-400 font-semibold' : 'text-slate-400'} truncate">
                                            ${isOnline ? 'En línea' : 'Desconectado'} · ${safePeerRole}
                                        </p>
                                    </div>
                                </div>
                                <div class="flex items-center gap-1.5 flex-shrink-0">
                                    ${win.minimized && unreadCount > 0 ? `<span class="bg-amber-500 text-slate-950 text-[10px] font-extrabold px-1.5 py-0.5 rounded-full">${unreadCount}</span>` : ''}
                                    <button onclick="chat.closeChat(${peer.id}, event)" class="text-slate-400 hover:text-white p-1 rounded-lg transition" title="Cerrar chat">
                                        <i class="ph-bold ph-x text-xs"></i>
                                    </button>
                                </div>
                            </div>

                            ${win.minimized ? '' : `
                            <div id="chat-body-${peer.id}" class="h-72 overflow-y-auto p-3.5 bg-slate-50 space-y-2.5 flex flex-col">
                                ${convMsgs.length === 0 ? `
                                    <div class="my-auto text-center px-4">
                                        <div class="w-10 h-10 rounded-full bg-emerald-100 text-emerald-700 flex items-center justify-center mx-auto mb-2">
                                            <i class="ph-duotone ph-chat-teardrop-text text-xl"></i>
                                        </div>
                                        <p class="text-xs font-semibold text-slate-600">Inicia una conversación con ${safePeerName}</p>
                                        <p class="text-[11px] text-slate-400 mt-0.5">Chat privado 1 a 1</p>
                                    </div>
                                ` : convMsgs.map(m => {
                                    const isMine = m.fromId === meId;
                                    const timeStr = new Date(m.timestamp).toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' });
                                    const safeText = security.esc(m.text);
                                    return `
                                        <div class="flex flex-col ${isMine ? 'items-end' : 'items-start'}">
                                            <div class="max-w-[82%] px-3 py-2 rounded-2xl text-xs leading-relaxed shadow-sm ${isMine ? 'bg-emerald-600 text-white rounded-br-sm' : 'bg-white text-slate-800 border border-slate-200 rounded-bl-sm'}">
                                                ${safeText}
                                            </div>
                                            <span class="text-[10px] text-slate-400 mt-0.5 px-1">${timeStr}</span>
                                        </div>
                                    `;
                                }).join('')}
                            </div>

                            <div class="p-2.5 bg-white border-t border-slate-200 flex items-center gap-2">
                                <input type="text" id="chat-input-${peer.id}" placeholder="Escribe un mensaje..." onkeypress="if(event.key==='Enter') chat.sendMessage(${peer.id})" class="flex-1 bg-slate-100 focus:bg-white border border-transparent focus:border-emerald-500 rounded-xl px-3 py-2 text-xs text-slate-800 outline-none transition">
                                <button onclick="chat.sendMessage(${peer.id})" class="bg-emerald-600 hover:bg-emerald-700 text-white w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0 transition shadow-sm" title="Enviar">
                                    <i class="ph-fill ph-paper-plane-right text-sm"></i>
                                </button>
                            </div>
                            `}
                        </div>
                    `;
                });

                dock.innerHTML = html;

                chat.openWindows.forEach(win => {
                    const inp = document.getElementById(`chat-input-${win.userId}`);
                    if (inp && savedDrafts[win.userId] !== undefined) inp.value = savedDrafts[win.userId];
                    const body = document.getElementById(`chat-body-${win.userId}`);
                    if (body) {
                        const prev = prevScrolls[win.userId];
                        const wasAtBottom = !prev || (prev.height - prev.top - prev.client < 40);
                        if (forceScrollBottom || wasAtBottom) body.scrollTop = body.scrollHeight;
                    }
                });
            }
        };

        // --- 5. CONTROLADOR DE INTERFAZ Y RUTAS ---
        const ui = {
            avatarBase64Store: null,
            avatarFileStore: null,
            selectedModuleProgId: null,

            toggleSidebar: () => {
                document.getElementById('sidebar').classList.toggle('collapsed');
            },

            toggleDropdown: (el, e) => {
                if (e) e.stopPropagation();
                const isActive = el.classList.contains('active');
                ui.closeAllDropdowns();
                if (!isActive) el.classList.add('active');
            },

            closeAllDropdowns: () => {
                document.querySelectorAll('.dropdown.active').forEach(d => d.classList.remove('active'));
            },

            showModal: (title, message) => {
                document.getElementById('sys-modal-title').innerText = title;
                document.getElementById('sys-modal-message').innerText = message;
                document.getElementById('sys-modal').classList.remove('hidden');
            },

            closeModal: () => {
                document.getElementById('sys-modal').classList.add('hidden');
            },

            showLogin: () => {
                document.getElementById('app-view').classList.add('hidden');
                document.getElementById('app-view').classList.remove('flex');
                document.getElementById('login-view').classList.remove('hidden');
            },

            showApp: () => {
                document.getElementById('login-view').classList.add('hidden');
                document.getElementById('app-view').classList.remove('hidden');
                document.getElementById('app-view').classList.add('flex');

                const fName = auth.currentUser.name.split(' ')[0];
                document.getElementById('header-user-name').innerText = fName;
                document.getElementById('header-user-role').innerText = auth.currentUser.role;

                if (auth.currentUser.avatar) {
                    document.getElementById('header-avatar').src = auth.currentUser.avatar;
                } else {
                    document.getElementById('header-avatar').src = `https://placehold.co/100x100/e2e8f0/475569?text=${encodeURIComponent(fName.charAt(0).toUpperCase())}`;
                }

                const ctxEl = document.getElementById('header-context');
                const searchCont = document.getElementById('header-search-container');
                const sideSub = document.getElementById('sidebar-inst-sub');

                if (auth.currentUser.role === 'admin') {
                    document.getElementById('header-inst-name').innerText = 'Panel Global Administrador';
                    if (sideSub) sideSub.innerText = 'Administración Global';
                    ctxEl.classList.remove('hidden');
                    searchCont.classList.remove('hidden');
                } else if (auth.currentInstitution) {
                    document.getElementById('header-inst-name').innerText = auth.currentInstitution.name;
                    if (sideSub) sideSub.innerText = auth.currentInstitution.name;
                    ctxEl.classList.remove('hidden');

                    if (auth.currentUser.role === 'rector' || auth.currentUser.role === 'coordinador') {
                        searchCont.classList.remove('hidden');
                    } else {
                        searchCont.classList.add('hidden');
                    }
                }

                ui.buildMenu();
                chat.refreshUI();
                ui.renderDashboard();
            },

            buildMenu: () => {
                const nav = document.getElementById('main-nav');
                nav.innerHTML = '';
                const role = auth.currentUser.role;

                const addItem = (label, icon, action) => {
                    nav.innerHTML += `
                        <button onclick="ui.setActiveNav(this); ${action}" class="nav-btn sidebar-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/10 transition text-sm text-left">
                            <i class="ph ${icon} text-lg flex-shrink-0"></i>
                            <span class="sidebar-text font-medium truncate">${label}</span>
                        </button>
                    `;
                };

                const addSection = (title) => {
                    nav.innerHTML += `<p class="sidebar-section-title px-3.5 pt-4 pb-1.5 text-[10px] font-bold uppercase tracking-widest text-emerald-400/80">${title}</p>`;
                };

                addItem('Inicio', 'ph-house', 'ui.renderDashboard()');

                if (role === 'admin') {
                    addSection('Administración Global');
                    addItem('Instituciones', 'ph-buildings', 'ui.renderInstitutions()');
                    addItem('Gestión de Rectores', 'ph-user-gear', 'ui.renderUsers()');
                } else if (role === 'rector') {
                    addSection('Institucional');
                    addItem('Usuarios y Perfiles', 'ph-users-three', 'ui.renderUsers()');
                    addItem('Programas de Estudio', 'ph-graduation-cap', 'ui.renderPrograms()');
                    addItem('Módulos de Programas', 'ph-stack', 'ui.renderProgramModules()');
                    addItem('Asignaciones', 'ph-chalkboard-teacher', 'ui.renderAssignments()');
                    addSection('Académico y Tesorería');
                    addItem('Estado de Tutores', 'ph-broadcast', 'ui.renderTutorsStatus()');
                    addItem('Ingresos y Egresos', 'ph-coins', 'ui.renderAccounting()');
                } else if (role === 'profesor') {
                    addSection('Académico');
                    addItem('Mis Salones', 'ph-chalkboard', 'ui.renderTeacherClassrooms()');
                    addItem('Registro de Notas', 'ph-exam', 'ui.renderGrades()');
                    addItem('Control de Asistencia', 'ph-calendar-check', 'ui.renderAttendance()');
                } else if (role === 'coordinador') {
                    addSection('Institucional');
                    if (auth.can('students', 'view') || auth.can('assignments', 'create')) addItem('Gestión de Usuarios', 'ph-users-three', 'ui.renderUsers()');
                    if (auth.can('programs', 'view')) addItem('Módulos de Programas', 'ph-stack', 'ui.renderProgramModules()');
                    if (auth.can('assignments', 'view')) addItem('Asignación Académica', 'ph-chalkboard-teacher', 'ui.renderAssignments()');
                    if (auth.can('accounting', 'view')) {
                        addSection('Seguimiento');
                        addItem('Estado de Tutores', 'ph-broadcast', 'ui.renderTutorsStatus()');
                        addItem('Ingresos y Egresos', 'ph-coins', 'ui.renderAccounting()');
                    }
                } else if (role === 'estudiante') {
                    addSection('Portal Estudiantil');
                    addItem('Mis Calificaciones', 'ph-exam', 'ui.renderStudentGrades()');
                    addItem('Mis Documentos', 'ph-files', 'ui.renderStudentDocs()');
                    addItem('Estado de Cuenta', 'ph-receipt', 'ui.renderStudentFinance()');
                }
            },

            setActiveNav: (btn) => {
                document.querySelectorAll('.nav-btn').forEach(b => {
                    b.classList.remove('bg-emerald-600', 'text-white', 'shadow-lg', 'shadow-emerald-600/20');
                    b.classList.add('text-slate-300');
                });
                if (btn) {
                    btn.classList.remove('text-slate-300');
                    btn.classList.add('bg-emerald-600', 'text-white', 'shadow-lg', 'shadow-emerald-600/20');
                }
            },

            performGlobalSearch: () => {
                const query = document.getElementById('global-search-input').value.toLowerCase();
                const resultsDiv = document.getElementById('global-search-results');

                if (query.length < 2) {
                    resultsDiv.classList.add('hidden');
                    return;
                }

                const role = auth.currentUser.role;
                let users = db.get('users');
                let instId = auth.currentUser.instId;

                if (role === 'admin') {
                    users = users.filter(u => u.role === 'rector');
                } else if (role === 'rector' || role === 'coordinador') {
                    users = users.filter(u => u.instId === instId && u.role !== 'admin');
                } else {
                    resultsDiv.classList.add('hidden');
                    return;
                }

                const matches = users.filter(u =>
                    u.name.toLowerCase().includes(query) ||
                    (u.lastName && u.lastName.toLowerCase().includes(query)) ||
                    (u.document && u.document.toLowerCase().includes(query)) ||
                    u.email.toLowerCase().includes(query)
                );

                if (matches.length === 0) {
                    resultsDiv.innerHTML = '<div class="p-4 text-sm text-slate-500 text-center">No se encontraron personas.</div>';
                    resultsDiv.classList.remove('hidden');
                    return;
                }

                const students = matches.filter(u => u.role === 'estudiante');
                const staff = matches.filter(u => u.role !== 'estudiante');

                let html = '';
                if (students.length > 0) {
                    html += `<div class="px-3.5 py-1.5 bg-slate-50 text-[11px] font-bold text-slate-400 uppercase tracking-wider">Estudiantes</div>`;
                    students.forEach(s => {
                        const avatarSrc = security.safeUrl(s.avatar, `https://placehold.co/100x100/e2e8f0/475569?text=${encodeURIComponent(security.esc(s.name.charAt(0)))}`);
                        html += `
                            <div onclick="ui.goToProfile(${s.id})" class="p-3 flex items-center gap-3 hover:bg-emerald-50/70 cursor-pointer border-b border-slate-100 transition">
                                <img src="${avatarSrc}" class="w-9 h-9 rounded-full object-cover">
                                <div>
                                    <p class="text-sm font-semibold text-slate-800 leading-tight">${security.esc(s.name)} ${security.esc(s.lastName || '')}</p>
                                    <p class="text-xs text-slate-500 font-mono">${s.document ? 'CC: ' + security.esc(s.document) : security.esc(s.email)}</p>
                                </div>
                            </div>
                        `;
                    });
                }

                if (staff.length > 0) {
                    html += `<div class="px-3.5 py-1.5 bg-slate-50 text-[11px] font-bold text-slate-400 uppercase tracking-wider border-t border-slate-100">Personal</div>`;
                    staff.forEach(s => {
                        const avatarSrc = security.safeUrl(s.avatar, `https://placehold.co/100x100/e2e8f0/475569?text=${encodeURIComponent(security.esc(s.name.charAt(0)))}`);
                        html += `
                            <div onclick="logic.editUser(${s.id})" class="p-3 flex items-center gap-3 hover:bg-emerald-50/70 cursor-pointer border-b border-slate-100 transition">
                                <img src="${avatarSrc}" class="w-9 h-9 rounded-full object-cover">
                                <div>
                                    <p class="text-sm font-semibold text-slate-800 leading-tight">${security.esc(s.name)} ${security.esc(s.lastName || '')}</p>
                                    <p class="text-[11px] text-emerald-600 uppercase font-bold">${security.esc(s.role)}</p>
                                </div>
                            </div>
                        `;
                    });
                }

                resultsDiv.innerHTML = html;
                resultsDiv.classList.remove('hidden');
            },

            goToProfile: (id) => {
                document.getElementById('global-search-results').classList.add('hidden');
                document.getElementById('global-search-input').value = '';
                ui.renderStudentDetail(id);
            },

            renderDashboard: () => {
                const container = document.getElementById('view-container');
                const user = auth.currentUser;
                const today = new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
                document.getElementById('sys-banner').classList.add('hidden');

                let html = `
                    <div class="mb-6">
                        <p class="text-xs font-semibold uppercase tracking-wider text-emerald-600 mb-1">${today}</p>
                        <h1 class="text-2xl sm:text-3xl font-extrabold text-slate-900">Bienvenido, ${security.esc(user.name.split(' ')[0].toUpperCase())}</h1>
                    </div>
                `;

                if (user.role === 'admin') {
                    const stats = db.cache.globalStats || {};
                    const instCount = stats.total_institutions ?? db.get('institutions').length;
                    const rectorsCount = stats.total_rectors ?? db.get('users').filter(u => u.role === 'rector').length;
                    const studentsCount = stats.total_students ?? 0;
                    const programsCount = stats.total_programs ?? 0;
                    html += `
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 hover:shadow-md transition flex items-center justify-between">
                            <div>
                                <h3 class="text-slate-400 font-bold uppercase text-xs tracking-wider mb-1">Instituciones</h3>
                                <p class="text-3xl font-extrabold text-slate-900">${instCount}</p>
                                <button onclick="ui.renderInstitutions()" class="mt-3 inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-600 hover:text-emerald-700">Gestionar <i class="ph-bold ph-arrow-right"></i></button>
                            </div>
                            <div class="w-12 h-12 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
                                <i class="ph-duotone ph-buildings text-2xl"></i>
                            </div>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 hover:shadow-md transition flex items-center justify-between">
                            <div>
                                <h3 class="text-slate-400 font-bold uppercase text-xs tracking-wider mb-1">Rectores</h3>
                                <p class="text-3xl font-extrabold text-slate-900">${rectorsCount}</p>
                                <button onclick="ui.renderUsers()" class="mt-3 inline-flex items-center gap-1.5 text-xs font-semibold text-amber-600 hover:text-amber-700">Gestionar <i class="ph-bold ph-arrow-right"></i></button>
                            </div>
                            <div class="w-12 h-12 rounded-2xl bg-amber-50 text-amber-600 flex items-center justify-center">
                                <i class="ph-duotone ph-user-gear text-2xl"></i>
                            </div>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 flex items-center justify-between">
                            <div>
                                <h3 class="text-slate-400 font-bold uppercase text-xs tracking-wider mb-1">Programas Globales</h3>
                                <p class="text-3xl font-extrabold text-slate-900">${programsCount}</p>
                                <span class="mt-3 inline-block text-[11px] text-slate-400 font-medium">Estadística agregada</span>
                            </div>
                            <div class="w-12 h-12 rounded-2xl bg-slate-100 text-slate-700 flex items-center justify-center">
                                <i class="ph-duotone ph-graduation-cap text-2xl"></i>
                            </div>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 flex items-center justify-between">
                            <div>
                                <h3 class="text-slate-400 font-bold uppercase text-xs tracking-wider mb-1">Estudiantes Globales</h3>
                                <p class="text-3xl font-extrabold text-slate-900">${studentsCount}</p>
                                <span class="mt-3 inline-block text-[11px] text-slate-400 font-medium">Estadística agregada</span>
                            </div>
                            <div class="w-12 h-12 rounded-2xl bg-teal-50 text-teal-700 flex items-center justify-center">
                                <i class="ph-duotone ph-student text-2xl"></i>
                            </div>
                        </div>
                    </div>`;
                } else {
                    html += `
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-8 flex flex-col md:flex-row items-center gap-8 mb-8">
                            <div class="w-48 h-40 bg-gradient-to-br from-slate-900 to-emerald-950 rounded-2xl flex items-center justify-center border border-emerald-500/20 flex-shrink-0 shadow-lg">
                                <i class="ph-duotone ph-buildings text-6xl text-emerald-400"></i>
                            </div>
                            <div>
                                <span class="inline-block px-3 py-1 rounded-full bg-emerald-50 text-emerald-700 text-xs font-bold mb-2 border border-emerald-200/70">Campus Activo</span>
                                <h2 class="text-xl font-bold text-slate-900 mb-2">Plataforma INTEGRA LMS</h2>
                                <p class="text-sm text-slate-600 mb-5 max-w-lg leading-relaxed">Bienvenido al sistema integrado de gestión académica y financiera. Utiliza el menú lateral izquierdo, el buscador superior o el chat institucional en vivo.</p>
                                <div class="flex flex-wrap gap-3">
                                    ${user.role === 'profesor' ? `<button onclick="ui.renderTeacherClassrooms()" class="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-5 py-2.5 rounded-xl text-sm transition shadow-md shadow-emerald-600/20 inline-flex items-center gap-2"><i class="ph-bold ph-chalkboard"></i> Ver Mis Salones</button>` : ''}
                                    <button onclick="ui.renderProfile()" class="bg-slate-900 hover:bg-slate-800 text-white font-semibold px-5 py-2.5 rounded-xl text-sm transition shadow-sm">Ver mi Perfil</button>
                                </div>
                            </div>
                        </div>
                    `;
                }
                container.innerHTML = html;
            },

            renderTeacherClassrooms: () => {
                if (auth.currentUser.role !== 'profesor') return;
                const container = document.getElementById('view-container');
                const teacherId = auth.currentUser.id;
                const myAssignments = db.get('assignments').filter(a => a.teacherId === teacherId);
                const allPrograms = db.get('programs');

                let html = `
                    <div class="text-xs text-slate-400 font-medium mb-2 flex items-center gap-1.5">
                        <span class="hover:text-emerald-600 cursor-pointer transition" onclick="ui.renderDashboard()">Inicio</span>
                        <span>&rsaquo;</span>
                        <span class="text-slate-600 font-semibold">Mis Salones</span>
                    </div>

                    <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-6">
                        <div>
                            <h2 class="text-2xl sm:text-3xl font-extrabold text-slate-900">Mis Salones Asignados</h2>
                            <p class="text-sm text-slate-500 mt-1">Consulta los grupos a tu cargo, sus módulos, estudiantes y accesos directos a notas y asistencia.</p>
                        </div>
                        <span class="self-start sm:self-auto px-3.5 py-1.5 rounded-full bg-emerald-50 border border-emerald-200 text-xs font-bold text-emerald-800">
                            ${myAssignments.length} salón${myAssignments.length === 1 ? '' : 'es'} asignado${myAssignments.length === 1 ? '' : 's'}
                        </span>
                    </div>
                `;

                if (myAssignments.length === 0) {
                    html += `
                        <div class="bg-white rounded-2xl border border-slate-200 p-12 text-center text-slate-400">
                            <i class="ph-duotone ph-chalkboard-teacher text-5xl mb-3 text-slate-300"></i>
                            <p class="font-semibold text-slate-600">Aún no tienes salones asignados.</p>
                            <p class="text-xs mt-1">Cuando la rectoría o coordinación te asigne un grupo, aparecerá automáticamente aquí.</p>
                        </div>
                    `;
                    container.innerHTML = html;
                    return;
                }

                html += `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">`;
                myAssignments.forEach(a => {
                    const prog = allPrograms.find(p => p.id === a.programId);
                    if (!prog) return;

                    const isClosed = prog.fechaCierre && (new Date() > new Date(prog.fechaCierre));
                    const studentsCount = (a.studentIds || []).length;
                    const modulosCount = (prog.modulos || []).length;
                    const horarioText = security.esc(prog.horarios && prog.horarios.length > 0
                        ? prog.horarios.map(h => h.texto).join(' · ')
                        : (prog.horario || 'Horario por definir'));
                    const tagLabel = security.esc(prog.code || 'Técnico');

                    html += `
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 border-t-4 border-t-emerald-500 p-5 flex flex-col justify-between hover:shadow-md transition">
                            <div>
                                <div class="flex items-center justify-between gap-2 mb-3">
                                    <span class="px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-[11px] font-bold tracking-wide">${tagLabel}</span>
                                    <span class="text-xs font-extrabold text-slate-800 uppercase tracking-tight">Salón ${security.esc(a.salon)}</span>
                                </div>

                                <h3 class="text-base font-extrabold text-slate-900 uppercase leading-snug mb-1.5 line-clamp-2 min-h-[2.75rem]">${security.esc(prog.nombre)}</h3>
                                <p class="text-xs text-slate-500 mb-4 truncate" title="${horarioText} · ${security.esc(prog.jornada || '')}">${horarioText} · ${security.esc(prog.jornada || 'Mañana')}</p>

                                <div class="flex flex-wrap items-center gap-2 pb-4 border-b border-slate-100">
                                    <button onclick="ui.viewClassroomStudents(${a.id})" class="px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50/70 hover:bg-slate-100 text-xs text-slate-700 transition">
                                        <strong class="font-extrabold text-slate-900">${studentsCount}</strong> estudiante${studentsCount === 1 ? '' : 's'}
                                    </button>
                                    <span class="px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50/70 text-xs text-slate-700">
                                        <strong class="font-extrabold text-slate-900">${modulosCount}</strong> módulo${modulosCount === 1 ? '' : 's'}
                                    </span>
                                    ${isClosed ? `<span class="px-2.5 py-1 rounded-lg bg-rose-50 text-rose-700 text-[11px] font-bold">Cerrado</span>` : ''}
                                </div>
                            </div>

                            <div class="pt-4 space-y-2.5">
                                <div class="flex items-center justify-between text-[11px] text-slate-400">
                                    <span>Cierre de notas:</span>
                                    <span class="font-semibold text-slate-600">${security.esc(prog.fechaCierre || 'Sin fecha')}</span>
                                </div>

                                <div class="grid grid-cols-2 gap-2 pt-1">
                                    <button onclick="ui.openTeacherGradesForAssign(${a.id})" class="px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold shadow-sm transition inline-flex items-center justify-center gap-1.5">
                                        <i class="ph-bold ph-exam"></i> Notas
                                    </button>
                                    <button onclick="ui.openTeacherAttendanceForAssign(${a.id})" class="px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold shadow-sm transition inline-flex items-center justify-center gap-1.5">
                                        <i class="ph-bold ph-calendar-check"></i> Asistencia
                                    </button>
                                </div>
                                <button onclick="ui.viewClassroomStudents(${a.id})" class="w-full px-3 py-2 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 transition">
                                    Ver lista de estudiantes
                                </button>
                            </div>
                        </div>
                    `;
                });
                html += `</div>`;
                container.innerHTML = html;
            },

            viewClassroomStudents: (assignId) => {
                const assign = db.get('assignments').find(a => a.id === assignId);
                if (!assign) return;
                const prog = db.get('programs').find(p => p.id === assign.programId);
                const allUsers = db.get('users');
                const ids = assign.studentIds || [];

                if (ids.length === 0) {
                    return ui.showModal(`Salón ${assign.salon}`, 'Este salón aún no tiene estudiantes matriculados.');
                }

                const list = ids.map((id, idx) => {
                    const s = allUsers.find(u => u.id === id);
                    return s ? `${idx + 1}. ${s.name} ${s.lastName || ''} (${s.docType || 'CC'}: ${s.document || 'N/A'}) · Tel: ${s.cel || s.tel || '-'}` : '';
                }).filter(Boolean).join('\n');

                ui.showModal(`${prog ? prog.nombre : 'Curso'} · Salón ${assign.salon} (${ids.length})`, list);
            },

            openTeacherGradesForAssign: (assignId) => {
                ui.renderGrades();
                setTimeout(() => {
                    const sel = document.getElementById('grade-prog');
                    if (sel) {
                        sel.value = assignId;
                        ui.onGradeProgramChange();
                    }
                }, 30);
            },

            openTeacherAttendanceForAssign: (assignId) => {
                ui.renderAttendance();
                setTimeout(() => {
                    const sel = document.getElementById('att-prog');
                    if (sel) {
                        sel.value = assignId;
                        ui.loadAttendanceList();
                    }
                }, 30);
            },

            renderInstitutions: () => {
                if (auth.currentUser.role !== 'admin') return;
                const container = document.getElementById('view-container');

                container.innerHTML = `
                    <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-6">
                        <div>
                            <h2 class="text-2xl font-extrabold text-slate-900">Gestión de Instituciones</h2>
                            <p class="text-sm text-slate-500">Administra las sedes educativas vinculadas a la plataforma.</p>
                        </div>
                        <button onclick="logic.showInstForm()" class="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-4 py-2.5 rounded-xl text-sm shadow-md shadow-emerald-600/20 inline-flex items-center gap-2"><i class="ph-bold ph-plus"></i> Nueva Institución</button>
                    </div>

                    <div class="bg-white p-3.5 rounded-2xl shadow-sm border border-slate-200 mb-5 flex items-center gap-3">
                        <i class="ph ph-magnifying-glass text-slate-400 text-xl ml-1"></i>
                        <input type="text" id="inst-search-input" onkeyup="ui.performInstSearch()" placeholder="Buscar institución por nombre o NIT..." class="w-full outline-none text-sm text-slate-700">
                    </div>

                    <div id="inst-form-container" class="hidden bg-white p-6 rounded-2xl shadow-md border border-slate-200 mb-6 border-t-4 border-t-emerald-500">
                        <h3 id="inst-form-title" class="font-bold text-lg mb-4 text-slate-900">Crear Institución</h3>
                        <input type="hidden" id="inst-id">
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-5">
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Razón Social / Nombre</label>
                                <input type="text" id="inst-name" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500" placeholder="Ej. Instituto Técnico Nacional">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">NIT</label>
                                <input type="text" id="inst-nit" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500" placeholder="Ej. 900.123.456-7">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Correo Contacto</label>
                                <input type="email" id="inst-email" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500" placeholder="info@institucion.com">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Tipo de Formación</label>
                                <select id="inst-type" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500 bg-white">
                                    <option value="Técnica">Técnica</option>
                                    <option value="Tecnológica">Tecnológica</option>
                                    <option value="Profesional">Profesional</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Estado</label>
                                <select id="inst-status" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500 bg-white">
                                    <option value="Activo">Activo</option>
                                    <option value="Inactivo">Inactivo</option>
                                </select>
                            </div>
                        </div>
                        <div class="flex gap-2.5">
                            <button onclick="logic.saveInstitution()" class="bg-emerald-600 text-white font-semibold px-5 py-2.5 rounded-xl text-sm hover:bg-emerald-700 transition">Guardar</button>
                            <button onclick="document.getElementById('inst-form-container').classList.add('hidden')" class="bg-slate-100 text-slate-700 font-semibold px-5 py-2.5 rounded-xl text-sm hover:bg-slate-200 transition">Cancelar</button>
                        </div>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase tracking-wider">
                                <tr>
                                    <th class="p-4">Razón Social</th>
                                    <th class="p-4">NIT</th>
                                    <th class="p-4">Correo</th>
                                    <th class="p-4">Formación</th>
                                    <th class="p-4">Estado</th>
                                    <th class="p-4 text-right">Acciones</th>
                                </tr>
                            </thead>
                            <tbody id="inst-table-body"></tbody>
                        </table>
                    </div>
                `;
                ui.performInstSearch();
            },

            performInstSearch: () => {
                const query = (document.getElementById('inst-search-input')?.value || '').toLowerCase();
                const tbody = document.getElementById('inst-table-body');
                if (!tbody) return;

                let results = db.get('institutions');
                if (query.length > 0) {
                    results = results.filter(i => i.name.toLowerCase().includes(query) || (i.nit && i.nit.toLowerCase().includes(query)));
                }

                if (results.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" class="p-10 text-center text-slate-400"><i class="ph-duotone ph-buildings text-4xl mb-2 text-slate-300"></i><br>No se encontraron instituciones registradas.</td></tr>`;
                    return;
                }

                tbody.innerHTML = results.map(i => {
                    const statusColor = i.status === 'Activo' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800';
                    return `
                        <tr class="border-b border-slate-100 hover:bg-slate-50/70 transition">
                            <td class="p-4 font-bold text-slate-800">${security.esc(i.name)}</td>
                            <td class="p-4 font-mono text-xs text-slate-500">${security.esc(i.nit || 'N/A')}</td>
                            <td class="p-4 text-xs text-slate-600">${security.esc(i.email || 'N/A')}</td>
                            <td class="p-4 text-slate-700">${security.esc(i.type || 'N/A')}</td>
                            <td class="p-4"><span class="px-2.5 py-1 rounded-full text-xs font-bold ${statusColor}">${security.esc(i.status || 'Activo')}</span></td>
                            <td class="p-4 text-right">
                                <button onclick="logic.showInstForm(${i.id})" class="text-emerald-700 hover:bg-emerald-100 px-3 py-1.5 bg-emerald-50 rounded-xl text-xs font-semibold transition"><i class="ph ph-pencil-simple mr-1"></i>Editar</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            },

            renderUsers: () => {
                const role = auth.currentUser.role;
                if (role !== 'admin' && role !== 'rector' && role !== 'coordinador') return;
                if (role === 'coordinador' && !auth.can('students', 'view') && !auth.can('assignments', 'create')) return ui.showModal('Error', 'No tiene permisos para acceder a Gestión de Usuarios.');

                const container = document.getElementById('view-container');

                if (role === 'admin') {
                    const rectors = db.get('users').filter(u => u.role === 'rector');
                    const institutions = db.get('institutions');

                    let html = `
                        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-6">
                            <div>
                                <h2 class="text-2xl font-extrabold text-slate-900">Gestión de Rectores</h2>
                                <p class="text-sm text-slate-500 mt-1">Crea y administra los rectores asignados a cada institución educativa.</p>
                            </div>
                            <button onclick="logic.openStaffModal()" class="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-4 py-2.5 rounded-xl text-sm shadow-md shadow-emerald-600/20 inline-flex items-center gap-2">
                                <i class="ph-bold ph-plus"></i> Nuevo Rector
                            </button>
                        </div>

                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                            <table class="w-full text-left text-sm">
                                <thead class="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase tracking-wider">
                                    <tr>
                                        <th class="p-4">Rector</th>
                                        <th class="p-4">Correo Electrónico</th>
                                        <th class="p-4">Institución Asignada</th>
                                        <th class="p-4 text-right">Acciones</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;

                    if (rectors.length === 0) {
                        html += `<tr><td colspan="4" class="p-10 text-center text-slate-400">
                            <i class="ph-duotone ph-user-gear text-4xl mb-2 text-slate-300"></i><br>
                            No hay rectores registrados. Crea primero una institución y luego haz clic en <strong>Nuevo Rector</strong>.
                        </td></tr>`;
                    } else {
                        rectors.forEach(r => {
                            const inst = institutions.find(i => i.id === r.instId);
                            const avatarSrc = security.safeUrl(r.avatar, `https://placehold.co/100x100/e2e8f0/475569?text=${encodeURIComponent(security.esc(r.name.charAt(0)))}`);
                            html += `
                                <tr class="border-b border-slate-100 hover:bg-slate-50/70 transition">
                                    <td class="p-4 flex items-center gap-3">
                                        <img src="${avatarSrc}" class="w-10 h-10 rounded-full object-cover border border-slate-200">
                                        <div>
                                            <p class="font-bold text-slate-800">${security.esc(r.name)}</p>
                                            <span class="text-[10px] uppercase font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-200">Rector</span>
                                        </div>
                                    </td>
                                    <td class="p-4 font-mono text-xs text-slate-600">${security.esc(r.email)}</td>
                                    <td class="p-4 font-semibold text-slate-700">${inst ? security.esc(inst.name) : '<span class="text-rose-500 text-xs">Sin institución</span>'}</td>
                                    <td class="p-4 text-right space-x-1">
                                        <button onclick="logic.editUser(${r.id})" class="text-emerald-700 hover:bg-emerald-100 px-3 py-1.5 bg-emerald-50 rounded-xl text-xs font-semibold transition" title="Editar perfil"><i class="ph ph-pencil-simple mr-1"></i>Editar</button>
                                        <button onclick="logic.deleteUser(${r.id})" class="text-rose-600 hover:bg-rose-100 px-3 py-1.5 bg-rose-50 rounded-xl text-xs font-semibold transition" title="Eliminar"><i class="ph ph-trash"></i></button>
                                    </td>
                                </tr>
                            `;
                        });
                    }

                    html += `</tbody></table></div>`;
                    container.innerHTML = html;
                    return;
                }

                if (role === 'rector') {
                    const coordinators = db.get('users').filter(u => u.role === 'coordinador' && u.instId === auth.currentUser.instId);
                    container.innerHTML = `
                        <div class="mb-6">
                            <h2 class="text-2xl font-extrabold text-slate-900">Gestión de Usuarios</h2>
                            <p class="text-sm text-slate-500 mt-1">Utiliza el buscador superior para consultar o editar perfiles específicos de estudiantes y personal, o configura los permisos de tus coordinadores.</p>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                            <div onclick="logic.openStaffModal()" class="bg-white p-8 rounded-2xl shadow-sm border border-slate-200 cursor-pointer hover:shadow-lg hover:border-slate-300 transition text-center flex flex-col items-center justify-center gap-4 group">
                                <div class="w-16 h-16 bg-slate-900 group-hover:bg-slate-800 rounded-2xl flex items-center justify-center text-amber-400 transition shadow-md">
                                    <i class="ph-duotone ph-identification-badge text-3xl"></i>
                                </div>
                                <div>
                                    <h3 class="font-bold text-slate-900 text-lg">Registrar Personal</h3>
                                    <p class="text-sm text-slate-500 mt-1">Crea cuentas para coordinadores y docentes de la institución.</p>
                                </div>
                            </div>
                            <div onclick="logic.openStudentModal()" class="bg-white p-8 rounded-2xl shadow-sm border border-slate-200 cursor-pointer hover:shadow-lg hover:border-emerald-300 transition text-center flex flex-col items-center justify-center gap-4 group">
                                <div class="w-16 h-16 bg-emerald-600 group-hover:bg-emerald-700 rounded-2xl flex items-center justify-center text-white transition shadow-md shadow-emerald-600/20">
                                    <i class="ph-duotone ph-student text-3xl"></i>
                                </div>
                                <div>
                                    <h3 class="font-bold text-slate-900 text-lg">Registrar Estudiante</h3>
                                    <p class="text-sm text-slate-500 mt-1">Inscribe nuevos estudiantes y asígnalos inmediatamente a un programa o salón.</p>
                                </div>
                            </div>
                        </div>

                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                            <div class="bg-slate-50 border-b border-slate-200 px-5 py-3.5 flex items-center justify-between">
                                <h3 class="font-bold text-slate-800 text-sm">Coordinadores de la Institución</h3>
                                <span class="text-xs text-slate-500">${coordinators.length} registrado${coordinators.length === 1 ? '' : 's'}</span>
                            </div>
                            <table class="w-full text-left text-sm">
                                <thead class="bg-white border-b border-slate-200 text-slate-500 text-xs uppercase">
                                    <tr><th class="p-4">Coordinador</th><th class="p-4">Correo</th><th class="p-4 text-right">Permisos y Perfil</th></tr>
                                </thead>
                                <tbody>
                                    ${coordinators.length === 0 ? `<tr><td colspan="3" class="p-8 text-center text-slate-400 text-xs">No hay coordinadores registrados aún.</td></tr>` : coordinators.map(c => `
                                        <tr class="border-b border-slate-100 hover:bg-slate-50/70">
                                            <td class="p-4 font-bold text-slate-800">${security.esc(c.name)}</td>
                                            <td class="p-4 font-mono text-xs text-slate-600">${security.esc(c.email)}</td>
                                            <td class="p-4 text-right">
                                                <button onclick="logic.editUser(${c.id})" class="bg-emerald-50 text-emerald-700 hover:bg-emerald-100 px-3.5 py-1.5 rounded-xl text-xs font-semibold border border-emerald-200 transition">
                                                    <i class="ph-bold ph-sliders mr-1"></i> Configurar Permisos
                                                </button>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    `;
                    return;
                }

                container.innerHTML = `
                    <div class="mb-6">
                        <h2 class="text-2xl font-extrabold text-slate-900">Gestión de Usuarios</h2>
                        <p class="text-sm text-slate-500 mt-1">Utiliza el buscador superior para consultar o editar perfiles específicos según tus permisos asignados.</p>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        ${auth.can('assignments', 'create') ? `
                        <div onclick="logic.openStaffModal()" class="bg-white p-8 rounded-2xl shadow-sm border border-slate-200 cursor-pointer hover:shadow-lg hover:border-slate-300 transition text-center flex flex-col items-center justify-center gap-4 group">
                            <div class="w-16 h-16 bg-slate-900 group-hover:bg-slate-800 rounded-2xl flex items-center justify-center text-amber-400 transition shadow-md">
                                <i class="ph-duotone ph-identification-badge text-3xl"></i>
                            </div>
                            <div>
                                <h3 class="font-bold text-slate-900 text-lg">Registrar Docente</h3>
                                <p class="text-sm text-slate-500 mt-1">Crea cuentas para docentes de la institución.</p>
                            </div>
                        </div>` : ''}
                        ${auth.can('students', 'create') ? `
                        <div onclick="logic.openStudentModal()" class="bg-white p-8 rounded-2xl shadow-sm border border-slate-200 cursor-pointer hover:shadow-lg hover:border-emerald-300 transition text-center flex flex-col items-center justify-center gap-4 group">
                            <div class="w-16 h-16 bg-emerald-600 group-hover:bg-emerald-700 rounded-2xl flex items-center justify-center text-white transition shadow-md shadow-emerald-600/20">
                                <i class="ph-duotone ph-student text-3xl"></i>
                            </div>
                            <div>
                                <h3 class="font-bold text-slate-900 text-lg">Registrar Estudiante</h3>
                                <p class="text-sm text-slate-500 mt-1">Inscribe nuevos estudiantes y asígnalos inmediatamente a un programa o salón.</p>
                            </div>
                        </div>` : ''}
                    </div>
                `;
            },

            renderPrograms: () => {
                if (auth.currentUser.role !== 'rector') return ui.showModal('Error', 'Acceso exclusivo para Rector.');
                const container = document.getElementById('view-container');

                container.innerHTML = `
                    <div class="text-xs text-slate-400 font-medium mb-2 flex items-center gap-1.5">
                        <span class="hover:text-emerald-600 cursor-pointer transition" onclick="ui.renderDashboard()">Inicio</span>
                        <span>&rsaquo;</span>
                        <span class="text-slate-600 font-semibold">Programas de estudio</span>
                    </div>

                    <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-5">
                        <div>
                            <h2 class="text-2xl sm:text-3xl font-extrabold text-slate-900">Programas de estudio</h2>
                        </div>
                        <button onclick="logic.showProgramForm()" class="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-4 py-2.5 rounded-xl text-sm shadow-md shadow-blue-600/20 inline-flex items-center gap-2">
                            <i class="ph-bold ph-plus"></i> Nuevo programa
                        </button>
                    </div>

                    <div class="bg-blue-50/80 border border-blue-200/80 text-blue-900 px-4 py-3 rounded-2xl mb-5 flex items-center gap-3 text-xs sm:text-sm">
                        <i class="ph ph-info text-blue-600 text-lg flex-shrink-0"></i>
                        <span>Cada tarjeta muestra la jornada, los días, el horario, los salones disponibles, los estudiantes matriculados y los módulos del pensum de cada programa.</span>
                    </div>

                    <div class="bg-white p-3.5 rounded-2xl shadow-sm border border-slate-200 mb-6 flex items-center gap-3">
                        <i class="ph ph-magnifying-glass text-slate-400 text-xl ml-1"></i>
                        <input type="text" id="prog-search-input" onkeyup="ui.performProgSearch()" placeholder="Buscar programa por código, nombre o salón..." class="w-full outline-none text-sm text-slate-700">
                    </div>

                    <div id="prog-form-container" class="hidden bg-white rounded-2xl shadow-md border border-slate-200 mb-6 overflow-hidden">
                        <div class="bg-slate-900 px-6 py-4 flex justify-between items-center text-white border-b border-emerald-500/30">
                            <h3 class="font-bold text-lg" id="prog-form-title">Nuevo Programa</h3>
                        </div>
                        <div class="p-6">
                            <input type="hidden" id="prog-id">
                            <h4 class="font-bold text-slate-800 border-b border-slate-100 pb-2 mb-4 text-xs uppercase tracking-wider flex items-center gap-1.5"><i class="ph-fill ph-info text-emerald-600 text-base"></i> Información General</h4>
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Código / Nivel</label>
                                    <input type="text" id="prog-code" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" placeholder="Ej. Técnico">
                                </div>
                                <div class="lg:col-span-2">
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Nombre del Programa / Curso</label>
                                    <input type="text" id="prog-name" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" placeholder="Ej. Auxiliar de Enfermería">
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Calendario</label>
                                    <select id="prog-cal" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                        <option value="A">Calendario A</option>
                                        <option value="B">Calendario B</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Año</label>
                                    <input type="number" id="prog-year" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" value="${new Date().getFullYear()}">
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Jornada</label>
                                    <select id="prog-jornada" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                        <option value="Mañana">Mañana</option>
                                        <option value="Tarde">Tarde</option>
                                        <option value="Noche">Noche</option>
                                        <option value="Fines de Semana">Fines de Semana</option>
                                        <option value="Mixta">Mixta</option>
                                    </select>
                                </div>
                                <div class="lg:col-span-2">
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Días y Horarios</label>
                                    <div class="flex gap-2 mb-2">
                                        <input type="text" id="prog-horario-input" class="flex-1 border border-slate-300 focus:border-emerald-500 px-3.5 py-2 rounded-xl text-sm outline-none" placeholder="Ej. L - MA - MI - J · 7:00 a 12:00" onkeypress="if(event.key === 'Enter') logic.addHorario()">
                                        <button type="button" onclick="logic.addHorario()" class="bg-slate-800 text-white px-3.5 py-2 rounded-xl text-sm hover:bg-slate-900 transition font-semibold">Agregar</button>
                                    </div>
                                    <ul id="prog-horario-list" class="space-y-1 max-h-24 overflow-y-auto pr-2"></ul>
                                </div>
                                <div class="lg:col-span-2">
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Salones / Grupos (Separados por coma)</label>
                                    <input type="text" id="prog-room" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" placeholder="Ej. 101, 102, 103">
                                </div>
                            </div>

                            <h4 class="font-bold text-slate-800 border-b border-slate-100 pb-2 mb-4 text-xs uppercase tracking-wider flex items-center gap-1.5"><i class="ph-fill ph-coins text-amber-500 text-base"></i> Información Financiera</h4>
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Costo Matrícula ($)</label>
                                    <input type="number" id="prog-matricula" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" value="0">
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Costo Mensualidad ($)</label>
                                    <input type="number" id="prog-mensualidad" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" value="0">
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Duración (Meses)</label>
                                    <input type="number" id="prog-meses" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" value="1">
                                </div>
                                <div>
                                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Costo Uniforme ($)</label>
                                    <input type="number" id="prog-uniforme" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none" value="0">
                                </div>
                            </div>

                            <div class="flex gap-2.5 justify-end pt-4 border-t border-slate-100">
                                <button onclick="document.getElementById('prog-form-container').classList.add('hidden')" class="bg-slate-100 text-slate-700 px-5 py-2.5 rounded-xl text-sm hover:bg-slate-200 transition font-semibold">Cancelar</button>
                                <button onclick="logic.saveProgram()" class="bg-emerald-600 text-white px-6 py-2.5 rounded-xl text-sm hover:bg-emerald-700 transition font-semibold shadow-md shadow-emerald-600/20">Guardar Programa</button>
                            </div>
                        </div>
                    </div>

                    <div id="prog-cards-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
                `;
                ui.performProgSearch();
            },

            performProgSearch: () => {
                const query = (document.getElementById('prog-search-input')?.value || '').toLowerCase();
                const grid = document.getElementById('prog-cards-grid');
                if (!grid) return;

                const instId = auth.currentUser.instId;
                let programs = db.get('programs').filter(p => p.instId === instId);
                const assignments = db.get('assignments').filter(a => a.instId === instId);

                if (query) {
                    programs = programs.filter(p =>
                        p.nombre.toLowerCase().includes(query) ||
                        (p.code && p.code.toLowerCase().includes(query)) ||
                        (p.salones && p.salones.join(' ').toLowerCase().includes(query))
                    );
                }

                if (programs.length === 0) {
                    grid.innerHTML = `
                        <div class="col-span-full bg-white rounded-2xl border border-slate-200 p-12 text-center text-slate-400">
                            <i class="ph-duotone ph-graduation-cap text-5xl mb-3 text-slate-300"></i>
                            <p class="font-semibold text-slate-600">No se encontraron programas de estudio.</p>
                            <p class="text-xs mt-1">Haz clic en <strong>+ Nuevo programa</strong> para registrar el primero.</p>
                        </div>
                    `;
                    return;
                }

                grid.innerHTML = programs.map(p => {
                    const isClosed = new Date() > new Date(p.fechaCierre);
                    const salones = security.esc(p.salones && p.salones.length > 0 ? p.salones.join(', ') : (p.salon || 'General'));
                    const numModulos = p.modulos ? p.modulos.length : 0;

                    const progAssignments = assignments.filter(a => a.programId === p.id);
                    const uniqueStudents = new Set();
                    progAssignments.forEach(a => (a.studentIds || []).forEach(id => uniqueStudents.add(id)));
                    const numEstudiantes = uniqueStudents.size;

                    const horarioText = security.esc(p.horarios && p.horarios.length > 0
                        ? p.horarios.map(h => h.texto).join(' · ')
                        : (p.horario || 'Horario por definir'));
                    const tagLabel = security.esc(p.code || 'Técnico');
                    const safeProgName = security.esc(p.nombre);
                    const safeJornada = security.esc(p.jornada || 'Mañana');

                    return `
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 border-t-4 border-t-amber-400 p-5 flex flex-col justify-between hover:shadow-md transition relative group">
                            <button onclick="logic.deleteProgram(${p.id})" class="absolute top-2.5 right-2.5 opacity-0 group-hover:opacity-100 text-slate-400 hover:text-rose-600 bg-white/90 hover:bg-rose-50 p-1.5 rounded-lg transition" title="Eliminar programa">
                                <i class="ph ph-trash text-sm"></i>
                            </button>

                            <div>
                                <div class="flex items-center justify-between gap-2 mb-3">
                                    <span class="px-2.5 py-0.5 rounded-full bg-amber-100/90 text-amber-800 text-[11px] font-bold tracking-wide">${tagLabel}</span>
                                    <span class="text-xs font-extrabold text-slate-800 uppercase tracking-tight truncate max-w-[55%]" title="Salones: ${salones}">Salón ${salones}</span>
                                </div>

                                <h3 class="text-base font-extrabold text-slate-900 uppercase leading-snug mb-1.5 line-clamp-2 min-h-[2.75rem]">${safeProgName}</h3>
                                <p class="text-xs text-slate-500 mb-4 truncate" title="${horarioText} · ${safeJornada}">${horarioText} · ${safeJornada}</p>

                                <div class="flex flex-wrap items-center gap-2 pb-4 border-b border-slate-100">
                                    <button onclick="ui.viewProgramStudents(${p.id})" class="px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50/60 hover:bg-slate-100 text-xs text-slate-700 transition">
                                        <strong class="font-extrabold text-slate-900">${numEstudiantes}</strong> estudiante${numEstudiantes === 1 ? '' : 's'}
                                    </button>
                                    <button onclick="ui.openProgramModules(${p.id})" class="px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50/60 hover:bg-emerald-50 hover:border-emerald-200 text-xs text-slate-700 transition">
                                        <strong class="font-extrabold text-slate-900">${numModulos}</strong> módulo${numModulos === 1 ? '' : 's'}
                                    </button>
                                </div>
                            </div>

                            <div class="pt-3.5 space-y-2.5">
                                <div class="flex items-center justify-between text-[11px] text-slate-400">
                                    <span>Cierre notas:</span>
                                    <div class="flex items-center gap-1">
                                        <input type="date" value="${security.escAttr(p.fechaCierre)}" onchange="logic.updateProgramDate(${p.id}, this.value)" class="border border-slate-200 rounded-lg px-2 py-0.5 text-[11px] text-slate-600 outline-none focus:border-emerald-500">
                                        ${isClosed ? '<span class="text-[9px] text-rose-600 font-bold px-1.5 py-0.5 bg-rose-50 rounded">CERRADO</span>' : ''}
                                    </div>
                                </div>

                                <div class="flex items-center justify-end gap-2">
                                    <button onclick="logic.editProgram(${p.id})" class="px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 transition">Editar</button>
                                    <button onclick="ui.viewProgramStudents(${p.id})" class="px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 transition">Ver estudiantes</button>
                                </div>
                                <div class="flex justify-end">
                                    <button onclick="ui.enrollStudentInProgram(${p.id})" class="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm shadow-blue-600/20 inline-flex items-center gap-1.5 transition">
                                        <i class="ph-bold ph-plus"></i> Estudiante
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');
            },

            openProgramModules: (progId) => {
                ui.selectedModuleProgId = progId;
                ui.renderProgramModules(progId);
            },

            viewProgramStudents: (progId) => {
                const prog = db.get('programs').find(p => p.id === progId);
                if (!prog) return;
                const assignments = db.get('assignments').filter(a => a.programId === progId);
                const allUsers = db.get('users');
                const studentIds = new Set();
                assignments.forEach(a => (a.studentIds || []).forEach(id => studentIds.add(id)));

                if (studentIds.size === 0) {
                    return ui.showModal(`Estudiantes · ${prog.nombre}`, 'Aún no hay estudiantes matriculados en este programa.');
                }

                const list = Array.from(studentIds).map((id, idx) => {
                    const s = allUsers.find(u => u.id === id);
                    const assign = assignments.find(a => (a.studentIds || []).includes(id));
                    return s ? `${idx + 1}. ${s.name} ${s.lastName || ''} (${s.docType || 'CC'}: ${s.document || 'N/A'}) · Salón ${assign ? assign.salon : '-'}` : '';
                }).filter(Boolean).join('\n');

                ui.showModal(`Estudiantes en ${prog.nombre} (${studentIds.size})`, list);
            },

            enrollStudentInProgram: (progId) => {
                logic.openStudentModal();
                setTimeout(() => {
                    const progSel = document.getElementById('std-programa');
                    if (progSel) {
                        progSel.value = progId;
                        ui.updateStdSalonDropdown();
                    }
                }, 40);
            },

            renderProgramModules: (preselectedProgId = null) => {
                const role = auth.currentUser.role;
                if (role !== 'rector' && role !== 'coordinador') return ui.showModal('Error', 'Acceso denegado.');
                if (role === 'coordinador' && !auth.can('programs', 'view')) return ui.showModal('Error', 'No tienes permiso para consultar programas.');
                const container = document.getElementById('view-container');
                const instId = auth.currentUser.instId;
                const programs = db.get('programs').filter(p => p.instId === instId);

                if (programs.length === 0) {
                    container.innerHTML = `
                        <div class="mb-6">
                            <h2 class="text-2xl font-extrabold text-slate-900">Módulos de programas</h2>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-10 text-center text-slate-500">
                            <i class="ph-duotone ph-stack text-5xl mb-3 text-slate-300"></i><br>
                            Primero debes crear al menos un <strong>Programa de Estudio</strong> para poder agregarle módulos.
                        </div>
                    `;
                    return;
                }

                if (preselectedProgId) ui.selectedModuleProgId = preselectedProgId;
                if (!ui.selectedModuleProgId || !programs.some(p => p.id == ui.selectedModuleProgId)) {
                    ui.selectedModuleProgId = programs[0].id;
                }

                const activeProg = programs.find(p => p.id == ui.selectedModuleProgId);
                const modules = activeProg.modulos || [];

                container.innerHTML = `
                    <div class="text-xs text-slate-400 font-medium mb-2 flex items-center gap-1.5">
                        <span class="hover:text-emerald-600 cursor-pointer transition" onclick="ui.renderDashboard()">Inicio</span>
                        <span>&rsaquo;</span>
                        ${role === 'rector' ? `<span class="hover:text-emerald-600 cursor-pointer transition" onclick="ui.renderPrograms()">Programas de estudio</span><span>&rsaquo;</span>` : ''}
                        <span class="text-slate-600 font-semibold">Módulos de programas</span>
                    </div>

                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
                        <h2 class="text-2xl sm:text-3xl font-extrabold text-slate-900">Módulos de programas</h2>
                        ${role === 'rector' ? `
                        <button onclick="ui.renderPrograms()" class="self-start sm:self-auto px-4 py-2 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-xs font-bold text-slate-700 inline-flex items-center gap-1.5 shadow-sm transition">
                            <i class="ph-bold ph-arrow-left"></i> Volver a Programas
                        </button>` : ''}
                    </div>

                    <div class="bg-emerald-50/70 border border-emerald-200/80 text-emerald-900 px-4 py-3 rounded-2xl mb-6 flex items-center gap-3 text-xs sm:text-sm">
                        <i class="ph ph-stack text-emerald-600 text-lg flex-shrink-0"></i>
                        <span>Selecciona un programa para organizar su pensum académico. Los docentes y estudiantes verán estos módulos ordenados en sus notas y reportes.</span>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-6 mb-6 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
                        <div class="w-full sm:max-w-md">
                            <label class="block text-xs font-bold text-slate-700 mb-2">Programa seleccionado</label>
                            <select id="mod-prog-select" onchange="ui.renderProgramModules(this.value)" class="w-full border border-slate-300 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20 px-4 py-2.5 rounded-xl text-sm font-medium text-slate-800 outline-none bg-white transition">
                                ${programs.map(p => `<option value="${p.id}" ${p.id == activeProg.id ? 'selected' : ''}>${security.esc(p.nombre)}</option>`).join('')}
                            </select>
                        </div>
                        <div class="flex items-center gap-2 self-start sm:self-auto">
                            <span class="px-3.5 py-1.5 rounded-full bg-emerald-50 border border-emerald-200 text-xs font-bold text-emerald-800">
                                ${modules.length} módulo${modules.length === 1 ? '' : 's'} registrado${modules.length === 1 ? '' : 's'}
                            </span>
                        </div>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <div class="p-4 sm:p-5 border-b border-slate-100 bg-slate-50/60 flex flex-col sm:flex-row gap-3">
                            <input type="text" id="new-prog-module-input" placeholder="Escribe el nombre del nuevo módulo (Ej. Bioseguridad, Farmacología)..." onkeypress="if(event.key==='Enter') logic.addProgramModule(${activeProg.id})" class="flex-1 border border-slate-300 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20 px-4 py-2.5 rounded-xl text-sm bg-white outline-none transition">
                            <button onclick="logic.addProgramModule(${activeProg.id})" class="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-5 py-2.5 rounded-xl text-sm shadow-sm shadow-emerald-600/20 inline-flex items-center justify-center gap-2 transition">
                                <i class="ph-bold ph-plus"></i> Agregar Módulo
                            </button>
                        </div>

                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-50/80 border-b border-slate-200 text-slate-600 text-xs font-bold">
                                <tr>
                                    <th class="py-3.5 px-5 w-16">#</th>
                                    <th class="py-3.5 px-4">Nombre del módulo</th>
                                    <th class="py-3.5 px-5 text-right w-32">Acciones</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-100">
                                ${modules.length === 0 ? `
                                    <tr>
                                        <td colspan="3" class="p-10 text-center text-slate-400 text-sm">
                                            Este programa aún no tiene módulos registrados. Escribe el nombre arriba para agregar el primero.
                                        </td>
                                    </tr>
                                ` : modules.map((m, idx) => `
                                    <tr class="hover:bg-slate-50/70 transition">
                                        <td class="py-3.5 px-5 font-semibold text-slate-400">${idx + 1}</td>
                                        <td class="py-3 px-4">
                                            <input type="text" value="${security.escAttr(m.nombre)}" onchange="logic.renameProgramModule(${activeProg.id}, ${m.id}, this.value)" class="w-full max-w-xl border border-slate-200 hover:border-slate-300 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/15 px-3.5 py-2 rounded-xl text-sm font-medium text-slate-800 bg-white outline-none transition">
                                        </td>
                                        <td class="py-3.5 px-5 text-right">
                                            <button onclick="logic.deleteProgramModule(${activeProg.id}, ${m.id})" class="text-slate-400 hover:text-rose-600 hover:bg-rose-50 px-2.5 py-1.5 rounded-xl text-xs font-semibold transition inline-flex items-center gap-1" title="Eliminar módulo">
                                                <i class="ph ph-trash text-base"></i> Quitar
                                            </button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            },

            renderAssignments: () => {
                const role = auth.currentUser.role;
                if (role !== 'rector' && role !== 'coordinador') return ui.showModal('Error', 'Acceso denegado.');
                if (role === 'coordinador' && !auth.can('assignments', 'view')) return ui.showModal('Error', 'No tiene permisos para acceder a Asignación Académica.');

                const container = document.getElementById('view-container');
                const instId = auth.currentUser.instId;
                const programs = db.get('programs').filter(p => p.instId === instId);
                const users = db.get('users').filter(u => u.instId === instId);
                const teachers = users.filter(u => u.role === 'profesor');
                const assignments = db.get('assignments').filter(a => a.instId === instId);

                let html = `
                    <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-6">
                        <div>
                            <h2 class="text-2xl font-extrabold text-slate-900">Asignación Académica</h2>
                            <p class="text-sm text-slate-500">Vincula docentes y estudiantes a los salones de cada programa.</p>
                        </div>
                        <button onclick="logic.showAssignForm()" class="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-4 py-2.5 rounded-xl text-sm shadow-md shadow-emerald-600/20 inline-flex items-center gap-2"><i class="ph-bold ph-plus"></i> Nueva Asignación</button>
                    </div>

                    <div id="assign-form-container" class="hidden bg-white p-6 rounded-2xl shadow-md border border-slate-200 mb-6 border-t-4 border-t-emerald-500">
                        <h3 class="font-bold text-lg mb-4 text-slate-900" id="assign-form-title">Asignar Profesor y Estudiantes a Salón</h3>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-5 mb-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Programa / Curso</label>
                                <select id="assign-prog" onchange="ui.updateAssignSalonDropdown()" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione un programa...</option>
                                    ${programs.map(p => `<option value="${p.id}">${p.code ? security.esc(p.code) + ' - ' : ''}${security.esc(p.nombre)}</option>`).join('')}
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Salón Específico</label>
                                <select id="assign-salon" onchange="ui.updateAssignStudents()" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione un curso primero</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Profesor Asignado</label>
                                <select id="assign-teacher" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione un profesor...</option>
                                    ${teachers.map(t => `<option value="${t.id}">${security.esc(t.name)} ${security.esc(t.lastName || '')}</option>`).join('')}
                                </select>
                            </div>
                        </div>
                        <div class="mb-6">
                            <label class="block text-xs font-semibold text-slate-700 mb-2">Seleccionar Estudiantes</label>
                            <div class="border border-slate-200 rounded-2xl p-3 h-48 overflow-y-auto bg-slate-50" id="assign-students-list">
                                <p class="text-sm text-slate-400">Seleccione un salón para ver los estudiantes disponibles.</p>
                            </div>
                        </div>
                        <div class="flex gap-2.5 justify-end">
                            <button onclick="document.getElementById('assign-form-container').classList.add('hidden')" class="bg-slate-100 text-slate-700 px-5 py-2.5 rounded-xl text-sm hover:bg-slate-200 transition font-semibold">Cancelar</button>
                            <button onclick="logic.saveAssignment()" class="bg-emerald-600 text-white px-6 py-2.5 rounded-xl text-sm hover:bg-emerald-700 transition font-semibold">Guardar Asignación</button>
                        </div>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase tracking-wider">
                                <tr><th class="p-4">Programa / Curso</th><th class="p-4">Salón</th><th class="p-4">Profesor</th><th class="p-4">Alumnos</th><th class="p-4 text-right">Acciones</th></tr>
                            </thead>
                            <tbody>
                `;

                if (assignments.length === 0) {
                    html += `<tr><td colspan="5" class="p-10 text-center text-slate-400"><i class="ph-duotone ph-chalkboard-teacher text-4xl mb-2 text-slate-300"></i><br>No hay asignaciones registradas.</td></tr>`;
                }

                assignments.forEach(a => {
                    const prog = programs.find(p => p.id === a.programId);
                    const teacher = teachers.find(t => t.id === a.teacherId);
                    if (prog) {
                        html += `
                            <tr class="border-b border-slate-100 hover:bg-slate-50/70 transition">
                                <td class="p-4 font-bold text-slate-800">${prog.code ? security.esc(prog.code) + ' - ' : ''}${security.esc(prog.nombre)}</td>
                                <td class="p-4 font-bold text-slate-900">${security.esc(a.salon || 'General')}</td>
                                <td class="p-4 text-slate-700">${teacher ? `<i class="ph-fill ph-chalkboard-teacher text-emerald-600 mr-1.5"></i> ${security.esc(teacher.name)} ${security.esc(teacher.lastName || '')}` : '<span class="text-rose-500 text-xs font-semibold">Sin asignar</span>'}</td>
                                <td class="p-4"><span class="bg-emerald-50 text-emerald-700 text-xs font-bold px-3 py-1 rounded-full border border-emerald-200">${a.studentIds.length} Estudiantes</span></td>
                                <td class="p-4 text-right space-x-1">
                                    <button onclick="logic.editAssignment(${a.id})" class="text-emerald-700 hover:bg-emerald-100 bg-emerald-50 px-3 py-1.5 rounded-xl text-xs font-semibold transition"><i class="ph ph-pencil-simple"></i></button>
                                    <button onclick="logic.deleteAssignment(${a.id})" class="text-rose-600 hover:bg-rose-100 bg-rose-50 px-3 py-1.5 rounded-xl text-xs font-semibold transition"><i class="ph ph-trash"></i></button>
                                </td>
                            </tr>
                        `;
                    }
                });

                html += `</tbody></table></div>`;
                container.innerHTML = html;
            },

            updateAssignSalonDropdown: () => {
                const progId = parseInt(document.getElementById('assign-prog').value);
                const salonSelect = document.getElementById('assign-salon');
                if (!progId) {
                    salonSelect.innerHTML = '<option value="">Seleccione un programa primero</option>';
                    return;
                }
                const prog = db.get('programs').find(p => p.id === progId);
                if (prog) {
                    const salones = prog.salones || (prog.salon ? [prog.salon] : []);
                    salonSelect.innerHTML = '<option value="">Seleccione un salón</option>' + salones.map(s => `<option value="${security.escAttr(s)}">${security.esc(s)}</option>`).join('');
                }
            },

            updateAssignStudents: () => {
                const progId = parseInt(document.getElementById('assign-prog').value);
                const salon = document.getElementById('assign-salon').value;
                const studentList = document.getElementById('assign-students-list');

                if (!progId || !salon) {
                    studentList.innerHTML = '<p class="text-sm text-slate-400">Seleccione un salón para ver los estudiantes disponibles.</p>';
                    return;
                }

                const students = db.get('users').filter(u => u.role === 'estudiante' && u.instId === auth.currentUser.instId);
                if (students.length === 0) {
                    studentList.innerHTML = '<p class="text-sm text-slate-400">No hay estudiantes en la institución.</p>';
                    return;
                }

                studentList.innerHTML = students.map(s => `
                    <label class="flex items-center gap-2.5 p-2 hover:bg-emerald-50/50 rounded-xl cursor-pointer border-b border-slate-100 last:border-0">
                        <input type="checkbox" name="assign-students" value="${s.id}" class="w-4 h-4 text-emerald-600 rounded focus:ring-emerald-500">
                        <span class="text-sm text-slate-700">${security.esc(s.name)} ${security.esc(s.lastName || '')} <span class="text-xs text-slate-400 ml-1">(${s.document ? 'CC:' + security.esc(s.document) : security.esc(s.email)})</span></span>
                    </label>
                `).join('');
            },

            updateStdSalonDropdown: () => {
                const progId = document.getElementById('std-programa').value;
                const salonSelect = document.getElementById('std-salon');
                const horarioSelect = document.getElementById('std-horario');

                if (!progId) {
                    salonSelect.innerHTML = '<option value="">Seleccione un curso primero</option>';
                    if (horarioSelect) horarioSelect.innerHTML = '<option value="">Seleccione un curso primero</option>';
                    return;
                }
                const prog = db.get('programs').find(p => p.id == progId);
                if (prog) {
                    const salones = prog.salones || (prog.salon ? [prog.salon] : []);
                    salonSelect.innerHTML = '<option value="">Seleccione un salón...</option>' + salones.map(s => `<option value="${security.escAttr(s)}">${security.esc(s)}</option>`).join('');

                    if (horarioSelect) {
                        const horarios = prog.horarios || [];
                        if (horarios.length > 0) {
                            horarioSelect.innerHTML = '<option value="">Seleccione un horario...</option>' + horarios.map(h => `<option value="${security.escAttr(h.texto)}">${security.esc(h.texto)} (${security.esc(prog.jornada || '')})</option>`).join('');
                        } else if (prog.horario) {
                            horarioSelect.innerHTML = `<option value="${security.escAttr(prog.horario)}">${security.esc(prog.horario)} (${security.esc(prog.jornada || '')})</option>`;
                        } else {
                            horarioSelect.innerHTML = `<option value="">Horario no definido</option>`;
                        }
                    }
                }
            },

            renderAccounting: () => {
                const role = auth.currentUser.role;
                if (role !== 'rector' && role !== 'coordinador') return ui.showModal('Error', 'Acceso denegado a Tesorería.');
                if (role === 'coordinador' && !auth.can('accounting', 'view')) return ui.showModal('Error', 'No tiene permisos para acceder a Tesorería.');

                const container = document.getElementById('view-container');
                const instId = auth.currentUser.instId;
                const records = db.get('accounting').filter(a => a.instId === instId);
                const totalBalance = records.reduce((acc, r) => r.type === 'ingreso' ? acc + r.amount : acc - r.amount, 0);

                let html = `
                    <div class="mb-6">
                        <h2 class="text-2xl font-extrabold text-slate-900">Tesorería y Contabilidad</h2>
                        <p class="text-sm text-slate-500">Control de ingresos, pagos estudiantiles y egresos institucionales.</p>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-200 border-l-4 border-l-emerald-500">
                            <h3 class="text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">Balance Consolidado</h3>
                            <p class="text-3xl font-extrabold ${totalBalance >= 0 ? 'text-emerald-600' : 'text-rose-600'}">$ ${totalBalance.toLocaleString()}</p>
                        </div>
                    </div>

                    <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 mb-6 border-t-4 border-t-emerald-500">
                        <h3 class="font-bold text-slate-900 mb-4" id="acc-form-title"><i class="ph-fill ph-bank mr-1.5 text-emerald-600"></i> Registrar Gastos e Ingresos Generales</h3>
                        <input type="hidden" id="acc-id">
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Fecha</label>
                                <input type="date" id="acc-date" value="${new Date().toISOString().split('T')[0]}" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Tipo de Movimiento</label>
                                <select id="acc-type" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500 bg-white">
                                    <option value="ingreso">Ingreso (+)</option>
                                    <option value="egreso">Egreso / Gasto (-)</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Monto ($)</label>
                                <input type="number" id="acc-amount" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500" placeholder="0.00">
                            </div>
                        </div>
                        <div class="mb-4">
                            <label class="block text-xs font-semibold text-slate-700 mb-1.5">Descripción de Operación</label>
                            <input type="text" id="acc-desc" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500" placeholder="Ej. Pago de servicios, material académico...">
                        </div>
                        <div class="flex gap-2.5">
                            <button id="btn-save-acc" onclick="logic.saveAccounting()" class="bg-emerald-600 text-white px-6 py-2.5 rounded-xl text-sm hover:bg-emerald-700 transition font-semibold shadow-sm">Registrar Movimiento</button>
                            <button id="btn-cancel-acc" onclick="logic.clearAccountingForm()" class="bg-slate-100 text-slate-700 px-5 py-2.5 rounded-xl text-sm hover:bg-slate-200 transition font-semibold hidden">Cancelar</button>
                        </div>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <div class="bg-slate-50 border-b border-slate-200 p-4 flex justify-between items-center">
                            <h3 class="font-bold text-slate-800">Historial de Transacciones (Libro Mayor)</h3>
                        </div>
                        <table class="w-full text-left text-sm">
                            <thead class="bg-white border-b border-slate-200 text-slate-500 text-xs uppercase tracking-wider">
                                <tr><th class="p-4">Fecha</th><th class="p-4">Ref.</th><th class="p-4">Tipo</th><th class="p-4">Descripción / Concepto</th><th class="p-4 text-right">Monto</th><th class="p-4 text-center">Acciones</th></tr>
                            </thead>
                            <tbody>
                `;

                if (records.length === 0) {
                    html += `<tr><td colspan="6" class="p-10 text-center text-slate-400"><i class="ph-duotone ph-coins text-4xl mb-2 text-slate-300"></i><br>No hay movimientos financieros registrados.</td></tr>`;
                } else {
                    records.reverse().forEach(r => {
                        const color = r.type === 'ingreso' ? 'text-emerald-600' : 'text-rose-600';
                        const sign = r.type === 'ingreso' ? '+' : '-';
                        const refStr = r.ref ? `<span class="font-mono text-xs bg-slate-100 px-2 py-0.5 rounded-lg border border-slate-200 text-slate-600">${security.esc(r.ref)}</span>` : '<span class="text-slate-400">-</span>';
                        html += `<tr class="border-b border-slate-50 hover:bg-slate-50/70 transition">
                            <td class="p-4 text-slate-500 text-xs">${security.esc(r.date)}</td>
                            <td class="p-4">${refStr}</td>
                            <td class="p-4 uppercase text-[11px] font-bold ${color}">${security.esc(r.type)}</td>
                            <td class="p-4 text-slate-800 font-medium">${security.esc(r.desc)} ${r.studentId ? '<span class="text-slate-400 text-xs ml-1">(Pago Alumno)</span>' : ''}</td>
                            <td class="p-4 text-right font-mono font-bold ${color}">${sign}$${Number(r.amount).toLocaleString()}</td>
                            <td class="p-4 text-center space-x-1">
                                ${r.studentId ? '<span class="text-[11px] text-slate-400">Autogenerado</span>' : `
                                <button onclick="logic.editAccounting(${r.id})" class="text-emerald-700 hover:bg-emerald-100 bg-emerald-50 px-2.5 py-1.5 rounded-xl text-xs transition"><i class="ph-bold ph-pencil-simple"></i></button>
                                <button onclick="logic.deleteAccounting(${r.id})" class="text-rose-600 hover:bg-rose-100 bg-rose-50 px-2.5 py-1.5 rounded-xl text-xs transition"><i class="ph-bold ph-trash"></i></button>
                                `}
                            </td>
                        </tr>`;
                    });
                }

                html += `</tbody></table></div>`;
                container.innerHTML = html;
            },

            renderTutorsStatus: () => {
                const role = auth.currentUser.role;
                if (role === 'coordinador' && !auth.can('accounting', 'view')) return ui.showModal('Error', 'No tiene permisos para ver el Estado de Tutores.');

                const container = document.getElementById('view-container');
                const teachers = db.get('users').filter(u => u.role === 'profesor' && u.instId === auth.currentUser.instId);

                let html = `
                    <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-6">
                        <div>
                            <h2 class="text-2xl font-extrabold text-slate-900">Estado de Conexión de Tutores</h2>
                            <p class="text-sm text-slate-500">Monitorea en tiempo real qué docentes están activos en la plataforma.</p>
                        </div>
                        <span class="self-start sm:self-auto px-3.5 py-1.5 rounded-full bg-emerald-50 border border-emerald-200 text-xs font-bold text-emerald-800 inline-flex items-center gap-1.5">
                            <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> Sincronización en vivo
                        </span>
                    </div>
                `;

                if (teachers.length === 0) {
                    html += `<div class="bg-white p-10 rounded-2xl border border-slate-200 text-center text-slate-400"><i class="ph-duotone ph-chalkboard-teacher text-4xl mb-2 text-slate-300"></i><br>No hay tutores registrados en la institución.</div>`;
                } else {
                    html += `<div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">`;
                    teachers.forEach(t => {
                        const avatarSrc = security.safeUrl(t.avatar, `https://placehold.co/100x100/e2e8f0/475569?text=${encodeURIComponent(security.esc(t.name.charAt(0)))}`);
                        const isOnline = t.isOnline === true;
                        const statusColor = isOnline ? 'bg-emerald-500' : 'bg-slate-400';
                        const statusText = isOnline ? 'En línea' : 'Desconectado';
                        const borderActive = isOnline ? 'border-emerald-300 shadow-emerald-100' : 'border-slate-200';

                        html += `
                            <div class="bg-white p-4 rounded-2xl shadow-sm border ${borderActive} flex items-center gap-4 transition-all">
                                <div class="relative flex-shrink-0">
                                    <img src="${avatarSrc}" class="w-12 h-12 rounded-full object-cover shadow-sm border border-slate-200">
                                    <div class="absolute bottom-0 right-0 w-3.5 h-3.5 rounded-full border-2 border-white ${statusColor}"></div>
                                </div>
                                <div class="min-w-0">
                                    <p class="text-sm font-bold text-slate-800 truncate leading-tight">${security.esc(t.name)}</p>
                                    <p class="text-xs font-semibold mt-1 ${isOnline ? 'text-emerald-600' : 'text-slate-400'}">${statusText}</p>
                                </div>
                            </div>
                        `;
                    });
                    html += `</div>`;
                }
                container.innerHTML = html;
            },

            renderGrades: () => {
                const container = document.getElementById('view-container');
                const teacherId = auth.currentUser.id;
                const myAssignments = db.get('assignments').filter(a => a.teacherId === teacherId);
                const allPrograms = db.get('programs');

                let progOptions = myAssignments.map(a => {
                    const p = allPrograms.find(prog => prog.id === a.programId);
                    return p ? `<option value="${a.id}">${security.esc(p.code || '')} - ${security.esc(p.nombre)} (Salón ${security.esc(a.salon)})</option>` : '';
                }).join('');

                let html = `<div class="mb-6"><h2 class="text-2xl font-extrabold text-slate-900">Registro de Notas por Módulo</h2></div>`;

                if (myAssignments.length === 0) {
                    html += `<div class="bg-white p-12 rounded-2xl border border-slate-200 text-center text-slate-400"><i class="ph-duotone ph-chalkboard-teacher text-5xl mb-3 text-slate-300"></i><br>No tienes salones asignados actualmente.</div>`;
                    container.innerHTML = html;
                    return;
                }

                html += `
                    <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 mb-6 border-t-4 border-t-emerald-500">
                        <h3 class="font-bold text-lg mb-4 text-slate-900">Registrar Nueva Calificación</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-5">
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Programa / Salón</label>
                                <select id="grade-prog" onchange="ui.onGradeProgramChange()" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione un salón...</option>
                                    ${progOptions}
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Módulo del Programa</label>
                                <select id="grade-module" onchange="ui.updateGradesView()" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione módulo...</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Estudiante</label>
                                <select id="grade-student" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione estudiante...</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Actividad / Corte</label>
                                <input type="text" id="grade-desc" placeholder="Ej. Taller 1, Examen Final" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Calificación (1.0 a 5.0)</label>
                                <input type="number" step="0.1" min="1.0" max="5.0" id="grade-val" placeholder="0.0" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none">
                            </div>
                        </div>
                        <div class="flex justify-between items-center">
                            <div id="grade-status-msg" class="text-sm font-semibold text-rose-600 hidden"><i class="ph-fill ph-warning-circle mr-1"></i> Programa Cerrado. Edición bloqueada.</div>
                            <button id="btn-save-grade" onclick="logic.saveGrade()" class="bg-emerald-600 text-white px-6 py-2.5 rounded-xl text-sm hover:bg-emerald-700 transition font-semibold shadow-md shadow-emerald-600/20 ml-auto">Guardar Nota</button>
                        </div>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <div class="bg-slate-50 border-b border-slate-200 p-4 flex justify-between items-center">
                            <h3 class="font-bold text-slate-800">Notas Registradas</h3>
                            <i class="ph-duotone ph-exam text-xl text-slate-400"></i>
                        </div>
                        <table class="w-full text-left text-sm">
                            <thead class="bg-white border-b border-slate-100 text-slate-500 text-xs uppercase tracking-wider">
                                <tr><th class="p-4">Estudiante</th><th class="p-4">Módulo</th><th class="p-4">Actividad</th><th class="p-4 text-center">Nota</th><th class="p-4 text-right">Acciones</th></tr>
                            </thead>
                            <tbody id="grades-table-body">
                                <tr><td colspan="5" class="p-10 text-center text-slate-400">Seleccione un salón y módulo para ver las calificaciones.</td></tr>
                            </tbody>
                        </table>
                    </div>
                `;
                container.innerHTML = html;
            },

            onGradeProgramChange: () => {
                const assignId = document.getElementById('grade-prog').value;
                const moduleSelect = document.getElementById('grade-module');
                if (!assignId) {
                    moduleSelect.innerHTML = '<option value="">Seleccione módulo...</option>';
                    ui.updateGradesView();
                    return;
                }
                const assignment = db.get('assignments').find(a => a.id == assignId);
                const program = assignment ? db.get('programs').find(p => p.id == assignment.programId) : null;
                const modules = program && program.modulos ? program.modulos : [];

                if (modules.length === 0) {
                    moduleSelect.innerHTML = '<option value="0">General (Sin módulos definidos)</option>';
                } else {
                    moduleSelect.innerHTML = '<option value="">Todos los módulos...</option>' +
                        modules.map(m => `<option value="${m.id}">${security.esc(m.nombre)}</option>`).join('');
                }
                ui.updateGradesView();
            },

            updateGradesView: () => {
                const assignId = document.getElementById('grade-prog').value;
                const selectedModuleId = document.getElementById('grade-module')?.value || '';
                const studentSelect = document.getElementById('grade-student');
                const tbody = document.getElementById('grades-table-body');
                const statusMsg = document.getElementById('grade-status-msg');
                const btnSave = document.getElementById('btn-save-grade');

                if (!assignId) {
                    studentSelect.innerHTML = '<option value="">Seleccione estudiante...</option>';
                    tbody.innerHTML = '<tr><td colspan="5" class="p-10 text-center text-slate-400">Seleccione un programa.</td></tr>';
                    statusMsg.classList.add('hidden');
                    btnSave.disabled = false;
                    btnSave.classList.remove('opacity-50', 'cursor-not-allowed');
                    return;
                }

                const assignment = db.get('assignments').find(a => a.id == assignId);
                const program = db.get('programs').find(p => p.id == assignment.programId);
                const isClosed = program && new Date() > new Date(program.fechaCierre);

                if (isClosed) {
                    statusMsg.classList.remove('hidden');
                    btnSave.disabled = true;
                    btnSave.classList.add('opacity-50', 'cursor-not-allowed');
                } else {
                    statusMsg.classList.add('hidden');
                    btnSave.disabled = false;
                    btnSave.classList.remove('opacity-50', 'cursor-not-allowed');
                }

                const prevStudent = studentSelect.value;
                const allUsers = db.get('users');
                let studentOptions = '<option value="">Seleccione estudiante...</option>';
                if (assignment) {
                    assignment.studentIds.forEach(id => {
                        const s = allUsers.find(u => u.id === id);
                        if (s) studentOptions += `<option value="${s.id}" ${s.id == prevStudent ? 'selected' : ''}>${security.esc(s.name)} ${security.esc(s.lastName || '')}</option>`;
                    });
                }
                studentSelect.innerHTML = studentOptions;

                let grades = db.get('grades').filter(g => g.programId == assignment.programId && assignment.studentIds.includes(g.studentId));
                if (selectedModuleId && selectedModuleId !== '0') {
                    grades = grades.filter(g => String(g.moduleId) === String(selectedModuleId));
                }

                if (grades.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="p-8 text-center text-slate-400">No hay notas registradas para esta selección.</td></tr>';
                    return;
                }

                const progModules = program && program.modulos ? program.modulos : [];

                tbody.innerHTML = grades.map(g => {
                    const s = allUsers.find(u => u.id === g.studentId);
                    const sName = s ? `${security.esc(s.name)} ${security.esc(s.lastName || '')}` : 'Desconocido';
                    const modObj = progModules.find(m => String(m.id) === String(g.moduleId));
                    const modLabel = modObj ? security.esc(modObj.nombre) : security.esc(g.moduleName || 'General');
                    const gradeColor = parseFloat(g.grade) >= 3.0 ? 'text-emerald-600' : 'text-rose-600';
                    return `
                        <tr class="border-b border-slate-50 hover:bg-slate-50/70 transition">
                            <td class="p-4 font-bold text-slate-800">${sName}</td>
                            <td class="p-4"><span class="px-2.5 py-1 rounded-lg bg-slate-100 text-slate-700 text-xs font-semibold">${modLabel}</span></td>
                            <td class="p-4 text-slate-600">${security.esc(g.desc)}</td>
                            <td class="p-4 text-center font-extrabold text-lg ${gradeColor}">${security.esc(g.grade)}</td>
                            <td class="p-4 text-right">
                                ${isClosed ? '<i class="ph-fill ph-lock-key text-slate-400"></i>' : `<button onclick="logic.deleteGrade(${g.id})" class="text-rose-600 hover:bg-rose-100 bg-rose-50 px-2.5 py-1.5 rounded-xl text-xs transition"><i class="ph ph-trash"></i></button>`}
                            </td>
                        </tr>
                    `;
                }).join('');
            },

            renderAttendance: () => {
                const container = document.getElementById('view-container');
                const teacherId = auth.currentUser.id;
                const myAssignments = db.get('assignments').filter(a => a.teacherId === teacherId);
                const allPrograms = db.get('programs');

                let progOptions = myAssignments.map(a => {
                    const p = allPrograms.find(prog => prog.id === a.programId);
                    return p ? `<option value="${a.id}">${security.esc(p.code || '')} - ${security.esc(p.nombre)} (Salón ${security.esc(a.salon)})</option>` : '';
                }).join('');

                const todayStr = new Date().toISOString().split('T')[0];
                let html = `<div class="mb-6"><h2 class="text-2xl font-extrabold text-slate-900">Control de Asistencia</h2></div>`;

                if (myAssignments.length === 0) {
                    html += `<div class="bg-white p-12 rounded-2xl border border-slate-200 text-center text-slate-400">No tienes salones asignados actualmente.</div>`;
                    container.innerHTML = html;
                    return;
                }

                html += `
                    <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 mb-6 border-t-4 border-t-emerald-500">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Programa / Salón</label>
                                <select id="att-prog" onchange="ui.loadAttendanceList()" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">
                                    <option value="">Seleccione un salón...</option>
                                    ${progOptions}
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-700 mb-1.5">Fecha de Clase</label>
                                <input type="date" id="att-date" onchange="ui.loadAttendanceList()" value="${todayStr}" max="${todayStr}" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none">
                            </div>
                        </div>
                        <div id="att-list-container" class="hidden mt-6">
                            <div class="flex justify-between items-center mb-3">
                                <h3 class="font-bold text-slate-800">Lista de Estudiantes</h3>
                                <span id="att-status-badge" class="px-3 py-1 text-xs font-bold rounded-full"></span>
                            </div>
                            <div class="border border-slate-200 rounded-2xl overflow-hidden">
                                <table class="w-full text-left text-sm">
                                    <thead class="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase">
                                        <tr><th class="p-3.5">Estudiante</th><th class="p-3.5 text-center">Asistencia</th></tr>
                                    </thead>
                                    <tbody id="att-tbody"></tbody>
                                </table>
                            </div>
                            <div class="mt-5 flex justify-end">
                                <button id="btn-save-att" onclick="ui.submitAttendance()" class="bg-emerald-600 text-white px-6 py-2.5 rounded-xl text-sm hover:bg-emerald-700 transition font-semibold shadow-md shadow-emerald-600/20">Guardar y Bloquear Asistencia</button>
                            </div>
                        </div>
                    </div>
                `;
                container.innerHTML = html;
            },

            loadAttendanceList: () => {
                const assignId = document.getElementById('att-prog').value;
                const dateStr = document.getElementById('att-date').value;
                const container = document.getElementById('att-list-container');
                const tbody = document.getElementById('att-tbody');
                const btnSave = document.getElementById('btn-save-att');
                const badge = document.getElementById('att-status-badge');

                if (!assignId || !dateStr) {
                    container.classList.add('hidden');
                    return;
                }

                const assignment = db.get('assignments').find(a => a.id == assignId);
                if (!assignment || assignment.studentIds.length === 0) {
                    container.classList.remove('hidden');
                    tbody.innerHTML = '<tr><td colspan="2" class="p-6 text-center text-slate-400">No hay estudiantes asignados a este salón.</td></tr>';
                    btnSave.classList.add('hidden');
                    badge.classList.add('hidden');
                    return;
                }

                const existingRecord = db.get('attendance').find(a => a.programId == assignment.programId && a.salon == assignment.salon && a.date === dateStr);
                const isReadonly = !!existingRecord;
                const allUsers = db.get('users');

                tbody.innerHTML = assignment.studentIds.map(id => {
                    const s = allUsers.find(u => u.id === id);
                    if (!s) return '';
                    const sName = `${security.esc(s.name)} ${security.esc(s.lastName || '')}`;
                    let isPresent = true;
                    if (existingRecord) {
                        const studentRec = existingRecord.records.find(r => r.studentId === id);
                        if (studentRec) isPresent = studentRec.present;
                    }
                    return `
                        <tr class="border-b border-slate-100 hover:bg-slate-50/70 transition">
                            <td class="p-3.5 font-semibold text-slate-800">${sName}</td>
                            <td class="p-3.5 text-center flex justify-center gap-6">
                                <label class="flex items-center gap-1.5 cursor-pointer">
                                    <input type="radio" name="att_${id}" value="true" ${isPresent ? 'checked' : ''} ${isReadonly ? 'disabled' : ''} class="w-4 h-4 text-emerald-600 focus:ring-emerald-500">
                                    <span class="text-sm ${isPresent && isReadonly ? 'text-emerald-600 font-bold' : ''}">Presente</span>
                                </label>
                                <label class="flex items-center gap-1.5 cursor-pointer">
                                    <input type="radio" name="att_${id}" value="false" ${!isPresent ? 'checked' : ''} ${isReadonly ? 'disabled' : ''} class="w-4 h-4 text-rose-600 focus:ring-rose-500">
                                    <span class="text-sm ${!isPresent && isReadonly ? 'text-rose-600 font-bold' : ''}">Ausente</span>
                                </label>
                            </td>
                        </tr>
                    `;
                }).join('');

                container.classList.remove('hidden');
                if (isReadonly) {
                    btnSave.classList.add('hidden');
                    badge.innerText = "Registrada - Solo Lectura";
                    badge.className = "px-3 py-1 text-xs font-bold rounded-full bg-emerald-100 text-emerald-800";
                } else {
                    btnSave.classList.remove('hidden');
                    badge.innerText = "Pendiente de Registro";
                    badge.className = "px-3 py-1 text-xs font-bold rounded-full bg-amber-100 text-amber-800";
                }
            },

            submitAttendance: () => {
                const assignId = document.getElementById('att-prog').value;
                const dateStr = document.getElementById('att-date').value;
                if (!assignId || !dateStr) return;
                logic.saveAttendance(assignId, dateStr);
            },

            renderStudentGrades: () => {
                const container = document.getElementById('view-container');
                const studentId = auth.currentUser.id;
                const myAssignments = db.get('assignments').filter(a => a.studentIds.includes(studentId));
                const allPrograms = db.get('programs');
                const allGrades = db.get('grades').filter(g => g.studentId === studentId);

                let html = `
                    <div class="mb-6">
                        <h2 class="text-2xl font-extrabold text-slate-900">Mis Módulos y Calificaciones</h2>
                        <p class="text-sm text-slate-500 mt-1">Consulta tu avance por cada módulo. El corte del módulo se calcula promediando todas las notas registradas en él.</p>
                    </div>
                `;

                if (myAssignments.length === 0) {
                    html += `<div class="bg-white p-12 rounded-2xl shadow-sm border border-slate-200 text-center text-slate-400"><i class="ph-duotone ph-exam text-6xl mb-3 text-slate-300"></i><br><span class="text-base font-medium">Aún no tienes programas asignados.</span></div>`;
                } else {
                    html += `<div class="space-y-8">`;
                    myAssignments.forEach(a => {
                        const prog = allPrograms.find(p => p.id === a.programId);
                        if (!prog) return;
                        const myGrades = allGrades.filter(g => g.programId === prog.id);
                        const progModules = prog.modulos || [];

                        const validModuleIds = new Set(progModules.map(m => String(m.id)));
                        const unassignedGrades = myGrades.filter(g => !g.moduleId || !validModuleIds.has(String(g.moduleId)));

                        let totalCutsSum = 0;
                        let evaluatedModulesCount = 0;

                        const renderModuleCard = (modTitle, modIndex, modGrades) => {
                            const count = modGrades.length;
                            const sum = modGrades.reduce((acc, item) => acc + (parseFloat(item.grade) || 0), 0);
                            const avg = count > 0 ? (sum / count) : null;

                            if (avg !== null) {
                                totalCutsSum += avg;
                                evaluatedModulesCount++;
                            }

                            const isApproved = avg !== null && avg >= 3.0;
                            const statusBadge = avg === null
                                ? `<span class="px-2.5 py-1 rounded-full bg-slate-100 text-slate-500 text-[11px] font-bold">Pendiente</span>`
                                : isApproved
                                    ? `<span class="px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 text-[11px] font-bold">Aprobado</span>`
                                    : `<span class="px-2.5 py-1 rounded-full bg-rose-100 text-rose-800 text-[11px] font-bold">En riesgo</span>`;

                            const avgColor = avg === null ? 'text-slate-400' : (isApproved ? 'text-emerald-600' : 'text-rose-600');

                            return `
                                <div class="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm flex flex-col justify-between">
                                    <div>
                                        <div class="px-4 py-3.5 bg-slate-50/90 border-b border-slate-100 flex items-center justify-between gap-2">
                                            <div class="flex items-center gap-2.5 min-w-0">
                                                <span class="w-6 h-6 rounded-lg bg-slate-900 text-white text-xs font-bold flex items-center justify-center flex-shrink-0">${modIndex}</span>
                                                <h4 class="font-bold text-slate-800 text-sm truncate" title="${security.escAttr(modTitle)}">${security.esc(modTitle)}</h4>
                                            </div>
                                            ${statusBadge}
                                        </div>

                                        <div class="p-4">
                                            ${count === 0 ? `
                                                <p class="text-xs text-slate-400 italic py-3 text-center">Sin notas registradas en este módulo todavía.</p>
                                            ` : `
                                                <div class="space-y-2">
                                                    ${modGrades.map(g => `
                                                        <div class="flex items-center justify-between text-xs py-1.5 border-b border-slate-50 last:border-0">
                                                            <span class="text-slate-600 font-medium">${security.esc(g.desc)}</span>
                                                            <span class="font-bold px-2 py-0.5 rounded ${parseFloat(g.grade) >= 3.0 ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700'}">${parseFloat(g.grade).toFixed(1)}</span>
                                                        </div>
                                                    `).join('')}
                                                </div>
                                            `}
                                        </div>
                                    </div>

                                    <div class="px-4 py-3 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
                                        <div>
                                            <span class="block text-[10px] font-bold uppercase tracking-wider text-slate-400">Corte del Módulo</span>
                                            <span class="text-[11px] text-slate-500">${count > 0 ? `${sum.toFixed(1)} ÷ ${count} nota${count === 1 ? '' : 's'}` : '0 notas'}</span>
                                        </div>
                                        <div class="text-right">
                                            <span class="text-xl font-extrabold ${avgColor}">${avg !== null ? avg.toFixed(2) : '--'}</span>
                                        </div>
                                    </div>
                                </div>
                            `;
                        };

                        const moduleCardsHtml = progModules.map((m, idx) => {
                            const mGrades = myGrades.filter(g => String(g.moduleId) === String(m.id));
                            return renderModuleCard(m.nombre, idx + 1, mGrades);
                        }).join('') + (unassignedGrades.length > 0 ? renderModuleCard('Evaluaciones Generales', progModules.length + 1, unassignedGrades) : '');

                        const generalAvg = evaluatedModulesCount > 0 ? (totalCutsSum / evaluatedModulesCount).toFixed(2) : '--';

                        html += `
                            <div class="bg-slate-50/70 rounded-3xl border border-slate-200 p-6">
                                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 mb-6 border-b border-slate-200">
                                    <div>
                                        <span class="px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 text-[11px] font-bold uppercase">Programa Matriculado</span>
                                        <h3 class="text-xl font-extrabold text-slate-900 mt-1.5">${security.esc(prog.nombre)}</h3>
                                        <p class="text-xs text-slate-500 mt-0.5">Salón: <strong>${security.esc(a.salon)}</strong> · ${progModules.length} módulo${progModules.length === 1 ? '' : 's'} en el pensum</p>
                                    </div>
                                    <div class="bg-white px-5 py-3 rounded-2xl border border-slate-200 shadow-sm text-left sm:text-right">
                                        <span class="block text-[10px] font-bold uppercase tracking-wider text-slate-400">Promedio General</span>
                                        <span class="text-2xl font-extrabold ${generalAvg !== '--' && parseFloat(generalAvg) >= 3.0 ? 'text-emerald-600' : 'text-slate-800'}">${generalAvg}</span>
                                    </div>
                                </div>

                                ${progModules.length === 0 && unassignedGrades.length === 0 ? `
                                    <div class="bg-white p-8 rounded-2xl border border-slate-200 text-center text-sm text-slate-400">
                                        Este programa aún no tiene módulos configurados por la institución.
                                    </div>
                                ` : `
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                                        ${moduleCardsHtml}
                                    </div>
                                `}
                            </div>
                        `;
                    });
                    html += `</div>`;
                }
                container.innerHTML = html;
            },

            renderStudentDocs: () => {
                const container = document.getElementById('view-container');
                const docs = db.get('docs').filter(d => d.studentId === auth.currentUser.id);
                let html = `
                    <div class="mb-6"><h2 class="text-2xl font-extrabold text-slate-900">Mis Documentos y Certificados</h2></div>
                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase tracking-wider">
                                <tr><th class="p-4">Fecha Carga</th><th class="p-4">Descripción / Tipo</th><th class="p-4">Archivo</th><th class="p-4 text-right">Acción</th></tr>
                            </thead>
                            <tbody>
                `;
                if (docs.length === 0) {
                    html += `<tr><td colspan="4" class="p-12 text-center text-slate-400"><i class="ph-duotone ph-files text-5xl mb-3 text-slate-300"></i><br>No tienes documentos cargados en tu perfil.</td></tr>`;
                } else {
                    docs.forEach(d => {
                        html += `
                            <tr class="border-b border-slate-100 hover:bg-slate-50/70 transition">
                                <td class="p-4 text-slate-500 text-xs font-mono">${security.esc(d.uploadDate)}</td>
                                <td class="p-4 font-bold text-slate-800">${security.esc(d.desc)}</td>
                                <td class="p-4 text-rose-600 font-mono text-xs"><i class="ph-fill ph-file-pdf mr-1.5"></i>${security.esc(d.fileName)}</td>
                                <td class="p-4 text-right">
                                    <button onclick="logic.downloadMockDoc(${d.id})" class="bg-emerald-50 text-emerald-700 hover:bg-emerald-100 px-3.5 py-1.5 rounded-xl text-xs transition font-semibold border border-emerald-200"><i class="ph-bold ph-download-simple mr-1"></i> Descargar</button>
                                </td>
                            </tr>
                        `;
                    });
                }
                html += `</tbody></table></div>`;
                container.innerHTML = html;
            },

            renderStudentFinance: () => {
                const container = document.getElementById('view-container');
                const user = auth.currentUser;
                const myPayments = db.get('accounting').filter(a => a.studentId === user.id);
                const totalPagado = myPayments.reduce((sum, p) => sum + p.amount, 0);

                let html = `
                    <div class="mb-6"><h2 class="text-2xl font-extrabold text-slate-900">Estado de Cuenta Financiero</h2></div>
                    <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 mb-8 w-full sm:w-72 border-l-4 border-l-emerald-500">
                        <p class="text-xs text-slate-400 uppercase font-bold tracking-wider mb-1">Total Abonado</p>
                        <p class="text-3xl font-extrabold text-emerald-600 mt-1">$ ${totalPagado.toLocaleString('es-CO')}</p>
                    </div>
                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <div class="bg-slate-50 border-b border-slate-200 p-4 flex justify-between items-center">
                            <h3 class="font-bold text-slate-800">Historial de Pagos</h3>
                            <i class="ph-duotone ph-receipt text-xl text-slate-400"></i>
                        </div>
                        <table class="w-full text-left text-sm">
                            <thead class="bg-white border-b border-slate-100 text-slate-500 text-xs uppercase tracking-wider">
                                <tr><th class="p-4">Fecha de Pago</th><th class="p-4">Concepto</th><th class="p-4">Referencia</th><th class="p-4 text-right">Valor Pagado</th><th class="p-4 text-center">Imprimir</th></tr>
                            </thead>
                            <tbody>
                `;
                if (myPayments.length === 0) {
                    html += `<tr><td colspan="5" class="p-10 text-center text-slate-400">No hay registros de pagos recientes.</td></tr>`;
                } else {
                    myPayments.reverse().forEach(p => {
                        html += `
                            <tr class="border-b border-slate-50 hover:bg-slate-50/70 transition">
                                <td class="p-4 text-slate-500 text-xs">${security.esc(p.date)}</td>
                                <td class="p-4 font-semibold text-slate-800">${security.esc(p.desc)}</td>
                                <td class="p-4"><span class="font-mono text-xs bg-emerald-50 text-emerald-700 px-2.5 py-1 rounded-lg border border-emerald-200">${security.esc(p.ref || 'N/A')}</span></td>
                                <td class="p-4 text-right font-bold text-emerald-600">$ ${Number(p.amount).toLocaleString()}</td>
                                <td class="p-4 text-center">
                                    <button onclick="ui.printReceipt(${p.id})" class="text-slate-400 hover:text-slate-800 p-1.5 rounded-lg hover:bg-slate-100 transition"><i class="ph-bold ph-printer text-lg"></i></button>
                                </td>
                            </tr>
                        `;
                    });
                }
                html += `</tbody></table></div>`;
                container.innerHTML = html;
            },

            renderProfile: () => {
                const container = document.getElementById('view-container');
                const user = auth.currentUser;
                ui.avatarBase64Store = user.avatar || null;
                ui.avatarFileStore = null;

                container.innerHTML = `
                    <div class="mb-6"><h2 class="text-2xl font-extrabold text-slate-900">Mi Perfil</h2></div>
                    <div class="bg-white p-6 sm:p-8 rounded-2xl shadow-sm border border-slate-200 mb-6 border-t-4 border-t-emerald-500 max-w-4xl mx-auto">
                        <div class="flex flex-col md:flex-row gap-8 items-start">
                            <div class="flex flex-col items-center gap-3 bg-slate-50 p-6 rounded-2xl border border-slate-200 w-full md:w-auto">
                                <div class="w-32 h-32 rounded-full border-4 border-white shadow-lg overflow-hidden relative group cursor-pointer bg-slate-100" onclick="document.getElementById('profile-avatar-upload').click()">
                                    <img id="profile-avatar-preview" src="${security.safeUrl(user.avatar, `https://placehold.co/150x150/e2e8f0/475569?text=${encodeURIComponent(security.esc(user.name.charAt(0)))}`)}" class="w-full h-full object-cover">
                                    <div class="absolute inset-0 bg-slate-900/50 flex flex-col items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                                        <i class="ph-fill ph-camera text-white text-2xl mb-1"></i>
                                        <span class="text-white text-[10px] font-bold">Cambiar Foto</span>
                                    </div>
                                </div>
                                <input type="file" id="profile-avatar-upload" class="hidden" accept="image/jpeg,image/png,image/webp" onchange="logic.handleAvatarUpload(event, 'profile-avatar-preview')">
                                <div class="text-center">
                                    <p class="text-sm font-extrabold text-slate-800 uppercase">${security.esc(user.role)}</p>
                                    <p class="text-xs text-slate-500 mt-0.5">${auth.currentInstitution ? security.esc(auth.currentInstitution.name) : 'Administración Global'}</p>
                                </div>
                            </div>

                            <div class="flex-1 w-full space-y-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                                    <div>
                                        <label class="block text-xs font-semibold text-slate-700 mb-1.5">Nombres</label>
                                        <input type="text" id="prof-name" value="${security.escAttr(user.name)}" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500">
                                    </div>
                                    ${user.role === 'estudiante' ? `
                                    <div>
                                        <label class="block text-xs font-semibold text-slate-700 mb-1.5">Apellidos</label>
                                        <input type="text" id="prof-lastname" value="${security.escAttr(user.lastName || '')}" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500">
                                    </div>
                                    <div>
                                        <label class="block text-xs font-semibold text-slate-700 mb-1.5 flex justify-between"><span>Documento / Usuario</span> <i class="ph-fill ph-lock-key text-slate-400"></i></label>
                                        <input type="text" id="prof-doc" value="${security.escAttr(user.document || '')}" class="w-full border border-slate-200 px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 text-slate-500 outline-none" readonly>
                                    </div>
                                    <div>
                                        <label class="block text-xs font-semibold text-slate-700 mb-1.5">Fecha de Nacimiento</label>
                                        <input type="date" id="prof-birth" value="${security.escAttr(user.birthDate || '')}" class="w-full border border-slate-300 px-3.5 py-2.5 rounded-xl text-sm outline-none focus:border-emerald-500">
                                    </div>
                                    ` : ''}
                                    <div class="${user.role !== 'estudiante' ? 'md:col-span-2' : ''}">
                                        <label class="block text-xs font-semibold text-slate-700 mb-1.5 flex justify-between"><span>Correo Electrónico</span> <i class="ph-fill ph-lock-key text-slate-400"></i></label>
                                        <input type="email" id="prof-email" value="${security.escAttr(user.email)}" class="w-full border border-slate-200 px-3.5 py-2.5 rounded-xl text-sm bg-slate-50 text-slate-500 outline-none" readonly>
                                    </div>
                                </div>

                                <div class="bg-slate-50/90 p-5 rounded-2xl border border-slate-200 space-y-4">
                                    <div class="flex items-center gap-2 border-b border-slate-200/80 pb-2.5">
                                        <i class="ph-fill ph-key text-emerald-600 text-lg"></i>
                                        <span class="text-xs font-bold uppercase tracking-wider text-slate-700">Seguridad y Cambio de Contraseña</span>
                                    </div>
                                    <p class="text-xs text-slate-500">Deja estos campos en blanco si deseas mantener tu contraseña actual.</p>
                                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                        <div>
                                            <label class="block text-xs font-semibold text-slate-700 mb-1.5">Contraseña Actual</label>
                                            <input type="password" id="prof-pass-current" placeholder="••••••••" class="w-full border border-slate-300 px-3.5 py-2 rounded-xl text-sm bg-white outline-none focus:border-emerald-500">
                                        </div>
                                        <div>
                                            <label class="block text-xs font-semibold text-slate-700 mb-1.5">Nueva Contraseña</label>
                                            <input type="password" id="prof-pass-new" placeholder="Mínimo 8 caracteres" class="w-full border border-slate-300 px-3.5 py-2 rounded-xl text-sm bg-white outline-none focus:border-emerald-500">
                                        </div>
                                        <div>
                                            <label class="block text-xs font-semibold text-slate-700 mb-1.5">Confirmar Nueva</label>
                                            <input type="password" id="prof-pass-confirm" placeholder="Repite la nueva" class="w-full border border-slate-300 px-3.5 py-2 rounded-xl text-sm bg-white outline-none focus:border-emerald-500">
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="mt-8 flex justify-end pt-4 border-t border-slate-100">
                            <button onclick="logic.updateProfile()" class="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-2.5 rounded-xl text-sm shadow-md shadow-emerald-600/20 transition font-semibold"><i class="ph-bold ph-floppy-disk mr-1"></i> Guardar Cambios</button>
                        </div>
                    </div>
                `;
            },

            renderStudentDetail: (id, activeTab = 'personal', activeSubtab = 'basica') => {
                const user = db.get('users').find(u => u.id === id);
                if (!user) return;

                const container = document.getElementById('view-container');
                const avatarSrc = security.safeUrl(user.avatar, `https://placehold.co/150x150/e2e8f0/475569?text=${encodeURIComponent(security.esc(user.name.charAt(0)))}`);
                const docText = user.docType ? `${security.esc(user.docType)} ${security.esc(user.document)}` : security.esc(user.document);
                const fullNames = user.lastName ? `${security.esc(user.name)} ${security.esc(user.lastName)}` : security.esc(user.name);
                const canRecoverAccount = (auth.currentUser.role === 'rector' || auth.currentUser.role === 'coordinador') && auth.currentUser.instId === user.instId;

                const docs = db.get('docs').filter(d => d.studentId === user.id);
                const req1 = docs.find(d => d.desc === 'Fotocopia documento de identificación');
                const req2 = docs.find(d => d.desc === 'Certificado de EPS / FOSYGA');
                const req3 = docs.find(d => d.desc === 'Fotocopia de diploma o acta de grado');

                const reqList = [
                    { title: 'Fotocopia documento de identificación', doc: req1 },
                    { title: 'Certificado de EPS / FOSYGA', doc: req2 },
                    { title: 'Fotocopia de diploma o acta de grado', doc: req3 }
                ];

                let requisitosHtml = reqList.map(req => {
                    if (req.doc) {
                        return `
                            <div class="flex items-center justify-between p-3.5 border-b border-slate-100">
                                <div class="flex items-center gap-2.5"><i class="ph-fill ph-check-circle text-emerald-500 text-lg"></i> <span class="text-sm text-slate-700 font-medium">${security.esc(req.title)}</span></div>
                                <div class="flex items-center gap-2">
                                    <button onclick="logic.downloadMockDoc(${req.doc.id})" class="text-xs font-bold text-emerald-700 hover:underline"><i class="ph-fill ph-file-pdf"></i> Ver adjunto</button>
                                    <button onclick="logic.deleteStudentProfileDoc(${req.doc.id}, ${user.id})" class="text-slate-400 hover:text-rose-500 ml-2"><i class="ph ph-trash"></i></button>
                                </div>
                            </div>
                        `;
                    } else {
                        return `
                            <div class="flex items-center justify-between p-3.5 border-b border-slate-100">
                                <div class="flex items-center gap-2.5"><i class="ph-fill ph-warning-circle text-amber-500 text-lg"></i> <span class="text-sm text-slate-700">${security.esc(req.title)}</span></div>
                                <div>
                                    <label class="cursor-pointer bg-slate-100 hover:bg-slate-200 text-slate-700 px-3.5 py-1.5 rounded-xl text-xs font-semibold border border-slate-200 transition">
                                        Cargar Documento
                                        <input type="file" class="hidden" accept="application/pdf" onchange="logic.saveRequiredDoc(${user.id}, '${security.escAttr(req.title)}', this)">
                                    </label>
                                </div>
                            </div>
                        `;
                    }
                }).join('');

                const otrosDocs = docs.filter(d => d.desc !== 'Fotocopia documento de identificación' && d.desc !== 'Certificado de EPS / FOSYGA' && d.desc !== 'Fotocopia de diploma o acta de grado');

                let personalHtml = `
                    <div class="flex gap-4 border-b border-slate-200 mb-6">
                        <button onclick="ui.renderStudentDetail(${user.id}, 'personal', 'basica')" class="px-4 py-2 text-sm font-bold border-b-2 transition ${activeSubtab === 'basica' ? 'border-emerald-600 text-emerald-600' : 'border-transparent text-slate-500 hover:text-slate-800'}">Información básica</button>
                        <button onclick="ui.renderStudentDetail(${user.id}, 'personal', 'documentacion')" class="px-4 py-2 text-sm font-bold border-b-2 transition ${activeSubtab === 'documentacion' ? 'border-emerald-600 text-emerald-600' : 'border-transparent text-slate-500 hover:text-slate-800'}">Documentación</button>
                    </div>

                    ${activeSubtab === 'basica' ? `
                    <div class="flex flex-wrap justify-end gap-3 mb-5">
                        ${canRecoverAccount ? `
                        <button onclick="logic.resetUserPassword(${user.id})" class="text-xs text-amber-800 bg-amber-50 hover:bg-amber-100 border border-amber-200 px-3.5 py-2 rounded-xl flex items-center gap-1.5 font-bold transition">
                            <i class="ph-bold ph-envelope-simple"></i> Enviar enlace de acceso
                        </button>` : ''}
                        <button onclick="logic.openStudentModal(${user.id})" class="text-xs text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 px-3.5 py-2 rounded-xl flex items-center gap-1.5 font-bold transition">
                            <i class="ph-bold ph-pencil-simple"></i> Editar información personal
                        </button>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3.5 text-sm">
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Nombres:</span> <span class="text-slate-800 font-medium">${security.esc(user.name)}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Apellidos:</span> <span class="text-slate-800 font-medium">${security.esc(user.lastName || '-')}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Identificación:</span> <span class="text-slate-800 font-mono">${docText || '-'}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Sexo:</span> <span class="text-slate-800">${user.sexo === 'M' ? 'Masculino' : user.sexo === 'F' ? 'Femenino' : '-'}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Teléfono:</span> <span class="text-slate-800">${security.esc(user.tel || '-')}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Celular:</span> <span class="text-slate-800">${security.esc(user.cel || '-')}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Correo:</span> <span class="text-slate-800">${security.esc(user.email)}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Dirección:</span> <span class="text-slate-800">${security.esc(user.dir || '-')}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Nacimiento:</span> <span class="text-slate-800">${security.esc(user.birthDate || '-')}</span></div>
                        <div class="flex"><span class="w-32 font-semibold text-slate-500">Barrio:</span> <span class="text-slate-800">${security.esc(user.barrio || '-')}</span></div>
                    </div>
                    ` : `
                    <p class="text-sm text-slate-600 mb-4">Documentación requerida y certificados adjuntos al estudiante.</p>
                    <div class="border border-slate-200 rounded-2xl mb-6 overflow-hidden">${requisitosHtml}</div>
                    <div class="border border-slate-200 rounded-2xl overflow-hidden">
                        <div class="bg-slate-50 p-3.5 border-b border-slate-200 font-bold text-slate-800 text-sm">Otros Documentos y Certificados</div>
                        <div class="p-4 border-b border-slate-200 bg-white">
                            <div class="flex flex-col md:flex-row gap-3 items-end">
                                <div class="flex-1 w-full">
                                    <label class="block text-xs font-semibold text-slate-600 mb-1">Descripción del Archivo</label>
                                    <input type="text" id="prof-doc-desc" class="w-full border border-slate-300 p-2.5 rounded-xl text-sm focus:border-emerald-500 outline-none" placeholder="Ej. Acta de Grado, Certificado de Notas...">
                                </div>
                                <div class="flex-1 w-full">
                                    <label class="block text-xs font-semibold text-slate-600 mb-1">Archivo PDF (máx. 10 MB)</label>
                                    <input type="file" id="prof-doc-file" accept="application/pdf" class="w-full border border-slate-300 p-2 rounded-xl text-sm outline-none bg-slate-50">
                                </div>
                                <button onclick="logic.saveStudentProfileDoc(${user.id})" class="bg-emerald-600 hover:bg-emerald-700 text-white px-5 py-2.5 rounded-xl text-sm font-semibold transition w-full md:w-auto">Subir Documento</button>
                            </div>
                        </div>
                        <div class="p-0">
                            ${otrosDocs.length === 0 ? '<p class="text-sm text-slate-400 text-center py-6">No hay otros documentos cargados en el perfil.</p>' :
                                otrosDocs.map(d => `
                                    <div class="flex items-center justify-between p-3.5 border-b border-slate-100 hover:bg-slate-50">
                                        <div>
                                            <p class="text-sm font-bold text-slate-800">${security.esc(d.desc)}</p>
                                            <p class="text-xs text-slate-500 font-mono"><i class="ph-fill ph-file-pdf text-rose-500 mr-1"></i>${security.esc(d.fileName)} &bull; ${security.esc(d.uploadDate)}</p>
                                        </div>
                                        <div class="flex items-center gap-2">
                                            <button onclick="logic.downloadMockDoc(${d.id})" class="text-emerald-700 hover:bg-emerald-100 px-3 py-1.5 bg-emerald-50 rounded-xl text-xs transition font-semibold">Descargar</button>
                                            <button onclick="logic.deleteStudentProfileDoc(${d.id}, ${user.id})" class="text-rose-500 hover:bg-rose-50 p-1.5 rounded-xl text-xs transition"><i class="ph ph-trash"></i></button>
                                        </div>
                                    </div>
                                `).join('')
                            }
                        </div>
                    </div>
                    `}
                `;

                const assignments = db.get('assignments').filter(a => a.studentIds.includes(user.id));
                const programs = db.get('programs');
                const grades = db.get('grades').filter(g => g.studentId === user.id);

                let academicHtml = '';
                if (assignments.length === 0) {
                    academicHtml = '<p class="text-sm text-slate-400 text-center py-10">El estudiante no está matriculado en ningún programa.</p>';
                } else {
                    assignments.forEach(a => {
                        const prog = programs.find(p => p.id === a.programId);
                        if (prog) {
                            const pGrades = grades.filter(g => g.programId === prog.id);
                            const progModules = prog.modulos || [];
                            const validModIds = new Set(progModules.map(m => String(m.id)));
                            const unassigned = pGrades.filter(g => !g.moduleId || !validModIds.has(String(g.moduleId)));

                            let sumCuts = 0;
                            let countCuts = 0;

                            const rowsHtml = progModules.map((m, idx) => {
                                const mGrades = pGrades.filter(g => String(g.moduleId) === String(m.id));
                                const avg = mGrades.length > 0 ? mGrades.reduce((acc, g) => acc + (parseFloat(g.grade) || 0), 0) / mGrades.length : null;
                                if (avg !== null) { sumCuts += avg; countCuts++; }
                                const notasText = mGrades.length > 0 ? mGrades.map(g => `${security.esc(g.desc)}: <strong>${security.esc(g.grade)}</strong>`).join(' · ') : '<span class="text-slate-400 italic">Sin notas</span>';
                                return `
                                    <tr class="border-b border-slate-50 hover:bg-slate-50/60">
                                        <td class="p-3.5 font-semibold text-slate-800">${idx + 1}. ${security.esc(m.nombre)}</td>
                                        <td class="p-3.5 text-xs text-slate-600">${notasText}</td>
                                        <td class="p-3.5 text-right font-extrabold ${avg === null ? 'text-slate-400' : (avg >= 3.0 ? 'text-emerald-600' : 'text-rose-600')}">${avg !== null ? avg.toFixed(2) : '--'}</td>
                                    </tr>
                                `;
                            }).join('') + (unassigned.length > 0 ? (() => {
                                const avg = unassigned.reduce((acc, g) => acc + (parseFloat(g.grade) || 0), 0) / unassigned.length;
                                sumCuts += avg; countCuts++;
                                return `
                                    <tr class="border-b border-slate-50">
                                        <td class="p-3.5 font-semibold text-slate-700">Evaluaciones Generales</td>
                                        <td class="p-3.5 text-xs text-slate-600">${unassigned.map(g => `${security.esc(g.desc)}: <strong>${security.esc(g.grade)}</strong>`).join(' · ')}</td>
                                        <td class="p-3.5 text-right font-extrabold ${avg >= 3.0 ? 'text-emerald-600' : 'text-rose-600'}">${avg.toFixed(2)}</td>
                                    </tr>
                                `;
                            })() : '');

                            const generalAvg = countCuts > 0 ? (sumCuts / countCuts).toFixed(2) : '--';

                            academicHtml += `
                                <div class="border border-slate-200 rounded-2xl mb-5 overflow-hidden">
                                    <div class="bg-slate-50 p-4 border-b border-slate-200 flex flex-wrap justify-between items-center gap-3">
                                        <div>
                                            <h4 class="font-bold text-slate-900">${security.esc(prog.nombre)}</h4>
                                            <p class="text-xs text-slate-500">Salón: ${security.esc(a.salon || 'N/A')} · Promedio General: <strong class="text-slate-800">${generalAvg}</strong></p>
                                        </div>
                                        <span class="bg-emerald-100 text-emerald-800 text-[11px] uppercase font-bold px-3 py-1 rounded-full">Matriculado</span>
                                    </div>
                                    <table class="w-full text-left text-sm bg-white">
                                        <thead class="border-b border-slate-100 text-xs text-slate-500 uppercase">
                                            <tr><th class="p-3.5">Módulo</th><th class="p-3.5">Notas Registradas</th><th class="p-3.5 text-right">Corte Módulo</th></tr>
                                        </thead>
                                        <tbody>
                                            ${progModules.length === 0 && unassigned.length === 0 ? `<tr><td colspan="3" class="p-5 text-center text-slate-400 text-xs">Este programa aún no tiene módulos definidos.</td></tr>` : rowsHtml}
                                        </tbody>
                                    </table>
                                </div>
                            `;
                        }
                    });
                }

                const payments = db.get('accounting').filter(r => r.studentId === user.id && r.type === 'ingreso');
                const totalPaid = payments.reduce((acc, curr) => acc + curr.amount, 0);

                let financeHtml = `
                    <div class="flex justify-between items-start mb-6 border-b border-slate-200 pb-4">
                        <div class="bg-emerald-50 px-5 py-3 rounded-2xl border border-emerald-200">
                            <p class="text-[11px] font-bold text-emerald-700 uppercase tracking-wider">Total Pagado</p>
                            <p class="text-2xl font-extrabold text-emerald-600">$ ${totalPaid.toLocaleString('es-CO')}</p>
                        </div>
                        <button onclick="ui.printAllReceipts()" class="border border-slate-300 text-slate-600 hover:bg-slate-50 px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition"><i class="ph-bold ph-printer"></i> Imprimir estado general</button>
                    </div>

                    <div class="bg-slate-50 p-4 rounded-2xl border border-slate-200 mb-6 flex flex-col sm:flex-row gap-3 items-end">
                        <div class="flex-[2] w-full">
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Concepto del pago</label>
                            <input type="text" id="prof-pay-desc" class="w-full border border-slate-300 p-2.5 rounded-xl text-sm outline-none bg-white focus:border-emerald-500" placeholder="Ej. Pensión Mes de Mayo">
                        </div>
                        <div class="flex-1 w-full">
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Valor ($)</label>
                            <input type="number" id="prof-pay-amount" class="w-full border border-slate-300 p-2.5 rounded-xl text-sm outline-none bg-white focus:border-emerald-500" placeholder="0">
                        </div>
                        <button onclick="logic.saveStudentPaymentProfile(${user.id})" class="bg-emerald-600 text-white hover:bg-emerald-700 px-5 py-2.5 rounded-xl text-sm font-semibold transition shadow-sm w-full sm:w-auto">+ Registrar Pago</button>
                    </div>

                    <table class="w-full text-left text-sm">
                        <thead class="border-b border-slate-200 text-xs text-slate-500 uppercase">
                            <tr><th class="py-2.5 px-2">N° Recibo</th><th class="py-2.5 px-2">Fecha</th><th class="py-2.5 px-2">Detalle Pago</th><th class="py-2.5 px-2 text-right">Valor</th></tr>
                        </thead>
                        <tbody>
                            ${payments.length === 0 ? `<tr><td colspan="4" class="py-8 text-center text-slate-400">Sin pagos registrados.</td></tr>` :
                                payments.reverse().map(p => `
                                    <tr class="border-b border-slate-50 hover:bg-slate-50">
                                        <td class="py-3 px-2 font-mono text-xs text-emerald-700 font-bold">${security.esc(p.ref || '-')}</td>
                                        <td class="py-3 px-2 text-slate-500 text-xs">${security.esc(p.date)}</td>
                                        <td class="py-3 px-2 text-slate-800 font-medium">${security.esc(p.desc)}</td>
                                        <td class="py-3 px-2 text-right font-bold text-slate-800 flex items-center justify-end gap-3">
                                            $ ${Number(p.amount).toLocaleString('es-CO')}
                                            <button onclick="ui.printReceipt(${p.id})" class="text-slate-400 hover:text-slate-700"><i class="ph-bold ph-printer"></i></button>
                                        </td>
                                    </tr>
                                `).join('')
                            }
                        </tbody>
                    </table>
                `;

                container.innerHTML = `
                    <div class="mb-4">
                        <button onclick="ui.renderUsers()" class="text-slate-500 hover:text-slate-900 text-sm flex items-center gap-1.5 font-semibold transition"><i class="ph-bold ph-arrow-left"></i> Volver a gestión de usuarios</button>
                    </div>
                    <div class="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
                        <div class="p-6 border-b border-slate-200 flex items-start gap-6 relative bg-gradient-to-r from-slate-50 to-white">
                            <div class="absolute left-0 top-0 w-2 h-full bg-emerald-500"></div>
                            <div class="flex-1 pl-2">
                                <h2 class="text-2xl sm:text-3xl font-extrabold text-slate-900 uppercase mb-2 leading-none">${fullNames}</h2>
                                <div class="flex flex-wrap items-center gap-2.5 mb-3">
                                    <span class="bg-slate-100 text-slate-700 font-mono text-xs px-2.5 py-1 rounded-lg border border-slate-200 font-semibold">${docText || 'Sin Documento'}</span>
                                    <span class="text-emerald-700 bg-emerald-50 font-bold text-xs px-2.5 py-1 rounded-full border border-emerald-200 flex items-center gap-1"><i class="ph-fill ph-check-circle"></i> Activo</span>
                                </div>
                                <p class="text-slate-500 text-xs font-bold uppercase tracking-wider flex items-center gap-1.5"><i class="ph-duotone ph-graduation-cap text-lg text-emerald-600"></i> Estudiante</p>
                            </div>
                            <img src="${avatarSrc}" class="w-20 h-20 sm:w-24 sm:h-24 rounded-2xl object-cover shadow-md bg-slate-100 border-2 border-white">
                        </div>

                        <div class="flex border-b border-slate-200 px-6 pt-3 gap-6 overflow-x-auto">
                            <button onclick="ui.renderStudentDetail(${user.id}, 'personal')" class="pb-3 text-sm font-bold border-b-2 whitespace-nowrap transition ${activeTab === 'personal' ? 'border-emerald-600 text-emerald-600' : 'border-transparent text-slate-500 hover:text-slate-800'}">Información personal</button>
                            <button onclick="ui.renderStudentDetail(${user.id}, 'academica')" class="pb-3 text-sm font-bold border-b-2 whitespace-nowrap transition ${activeTab === 'academica' ? 'border-emerald-600 text-emerald-600' : 'border-transparent text-slate-500 hover:text-slate-800'}">Información académica</button>
                            <button onclick="ui.renderStudentDetail(${user.id}, 'financiera')" class="pb-3 text-sm font-bold border-b-2 whitespace-nowrap transition ${activeTab === 'financiera' ? 'border-emerald-600 text-emerald-600' : 'border-transparent text-slate-500 hover:text-slate-800'}">Información financiera</button>
                        </div>

                        <div class="p-6 bg-white min-h-[400px]">
                            ${activeTab === 'personal' ? personalHtml : activeTab === 'academica' ? academicHtml : financeHtml}
                        </div>
                    </div>
                `;
            },

            printReceipt: (id) => {
                const record = db.get('accounting').find(r => r.id === id);
                if (!record) return;
                const user = db.get('users').find(u => u.id === record.studentId);
                const userName = user ? `${security.esc(user.name)} ${security.esc(user.lastName || '')}` : 'Estudiante';
                const instName = auth.currentInstitution ? security.esc(auth.currentInstitution.name) : 'INTEGRA LMS';

                const printArea = document.createElement('div');
                printArea.id = 'print-area';
                printArea.className = 'bg-white p-10 font-sans text-gray-800 max-w-2xl mx-auto';
                printArea.innerHTML = `
                    <div class="border-b-2 border-gray-800 pb-4 mb-6 text-center">
                        <h1 class="text-2xl font-bold uppercase">${instName}</h1>
                        <p class="text-gray-600">Recibo de Caja Oficial</p>
                    </div>
                    <div class="flex justify-between mb-8">
                        <div>
                            <p class="text-sm text-gray-500 uppercase font-bold">Recibo N°</p>
                            <p class="text-xl font-mono">${security.esc(record.ref)}</p>
                        </div>
                        <div class="text-right">
                            <p class="text-sm text-gray-500 uppercase font-bold">Fecha</p>
                            <p class="text-lg">${security.esc(record.date)}</p>
                        </div>
                    </div>
                    <div class="mb-8 p-4 bg-gray-50 rounded border border-gray-200">
                        <p class="text-xs text-gray-500 uppercase mb-1">Recibido de:</p>
                        <p class="text-lg font-semibold">${userName}</p>
                        ${user && user.document ? `<p class="text-sm text-gray-600 font-mono">CC/TI: ${security.esc(user.document)}</p>` : ''}
                    </div>
                    <table class="w-full text-left mb-8 border-collapse">
                        <thead>
                            <tr class="border-b border-gray-300">
                                <th class="py-2 text-gray-600 uppercase text-xs">Concepto / Descripción</th>
                                <th class="py-2 text-right text-gray-600 uppercase text-xs">Valor</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr class="border-b border-gray-100">
                                <td class="py-4 text-lg">${security.esc(record.desc)}</td>
                                <td class="py-4 text-right font-bold text-xl">$ ${Number(record.amount).toLocaleString('es-CO')}</td>
                            </tr>
                        </tbody>
                    </table>
                    <div class="text-center mt-12 pt-8 border-t border-gray-200 text-sm text-gray-500">
                        Documento generado automáticamente por INTEGRA LMS.<br>Firma Autorizada: _______________________
                    </div>
                `;
                document.body.appendChild(printArea);
                window.print();
                document.body.removeChild(printArea);
            },

            printAllReceipts: () => {
                ui.showModal('Info', 'Función de impresión general en desarrollo.');
            }
        };

        // --- 6. LÓGICA DE NEGOCIO ---
        const logic = {
            currentHorarios: [],

            addHorario: () => {
                const input = document.getElementById('prog-horario-input');
                if (!input) return;
                const val = input.value.trim();
                if (val) {
                    logic.currentHorarios.push({ id: Date.now() + Math.random(), texto: val });
                    input.value = '';
                    logic.renderHorariosList();
                }
            },

            removeHorario: (id) => {
                logic.currentHorarios = logic.currentHorarios.filter(h => h.id !== id);
                logic.renderHorariosList();
            },

            renderHorariosList: () => {
                const list = document.getElementById('prog-horario-list');
                if (!list) return;
                if (logic.currentHorarios.length === 0) {
                    list.innerHTML = '<li class="text-xs text-slate-400 italic py-1">No hay horarios agregados.</li>';
                    return;
                }
                list.innerHTML = logic.currentHorarios.map(h => `
                    <li class="flex justify-between items-center bg-slate-100 px-3 py-1.5 rounded-xl text-xs border border-slate-200">
                        <span class="text-slate-700 flex items-center gap-1.5 font-medium"><i class="ph-fill ph-clock text-emerald-600"></i> ${security.esc(h.texto)}</span>
                        <button type="button" onclick="logic.removeHorario(${h.id})" class="text-rose-500 hover:text-rose-700 p-1"><i class="ph-bold ph-x"></i></button>
                    </li>
                `).join('');
            },

            addProgramModule: (progId) => {
                const input = document.getElementById('new-prog-module-input');
                if (!input) return;
                const val = input.value.trim();
                if (!val) return ui.showModal('Aviso', 'Escribe el nombre del módulo antes de agregarlo.');

                const programs = db.get('programs');
                const idx = programs.findIndex(p => p.id == progId);
                if (idx > -1) {
                    if (!programs[idx].modulos) programs[idx].modulos = [];
                    programs[idx].modulos.push({ id: Date.now() + Math.floor(Math.random() * 1000), nombre: val });
                    db.set('programs', programs);
                    ui.renderProgramModules(progId);
                    setTimeout(() => {
                        const newInp = document.getElementById('new-prog-module-input');
                        if (newInp) newInp.focus();
                    }, 30);
                }
            },

            renameProgramModule: (progId, modId, newName) => {
                const trimmed = newName.trim();
                if (!trimmed) return;
                const programs = db.get('programs');
                const pIdx = programs.findIndex(p => p.id == progId);
                if (pIdx > -1 && programs[pIdx].modulos) {
                    const mIdx = programs[pIdx].modulos.findIndex(m => m.id == modId);
                    if (mIdx > -1) {
                        programs[pIdx].modulos[mIdx].nombre = trimmed;
                        db.set('programs', programs);
                    }
                }
            },

            deleteProgramModule: (progId, modId) => {
                const programs = db.get('programs');
                const pIdx = programs.findIndex(p => p.id == progId);
                if (pIdx > -1 && programs[pIdx].modulos) {
                    programs[pIdx].modulos = programs[pIdx].modulos.filter(m => m.id != modId);
                    db.set('programs', programs);
                }
                ui.renderProgramModules(progId);
            },

            showInstForm: (id = null) => {
                document.getElementById('inst-form-container').classList.remove('hidden');
                const title = document.getElementById('inst-form-title');
                if (id) {
                    const inst = db.get('institutions').find(i => i.id === id);
                    title.innerText = 'Editar Institución';
                    document.getElementById('inst-id').value = inst.id;
                    document.getElementById('inst-name').value = inst.name;
                    document.getElementById('inst-nit').value = inst.nit || '';
                    document.getElementById('inst-email').value = inst.email || '';
                    document.getElementById('inst-type').value = inst.type || 'Técnica';
                    document.getElementById('inst-status').value = inst.status || 'Activo';
                } else {
                    title.innerText = 'Crear Institución';
                    document.getElementById('inst-id').value = '';
                    document.getElementById('inst-name').value = '';
                    document.getElementById('inst-nit').value = '';
                    document.getElementById('inst-email').value = '';
                    document.getElementById('inst-type').value = 'Técnica';
                    document.getElementById('inst-status').value = 'Activo';
                }
            },

            saveInstitution: async () => {
                const id = document.getElementById('inst-id').value;
                const name = document.getElementById('inst-name').value.trim();
                const nit = document.getElementById('inst-nit').value.trim();
                const email = document.getElementById('inst-email').value.trim();
                const type = document.getElementById('inst-type').value;
                const status = document.getElementById('inst-status').value;

                if (!name || !nit) return ui.showModal('Error', 'Debe diligenciar Razón Social/Nombre y el NIT.');

                let insts = db.get('institutions');
                if (id) {
                    const index = insts.findIndex(i => i.id == id);
                    if (index > -1) insts[index] = { ...insts[index], name, nit, email, type, status };
                } else {
                    insts.push({ id: Date.now(), name, nit, email, type, status });
                }

                const ok = await db.set('institutions', insts);
                if (!ok) return;
                document.getElementById('inst-form-container').classList.add('hidden');
                ui.performInstSearch();
                ui.showModal('Éxito', id ? 'Institución actualizada correctamente.' : 'Institución guardada correctamente.');
            },

            handleAvatarUpload: (event, targetImgId = 'u-avatar-preview') => {
                const file = event.target.files[0];
                if (file) {
                    const err = security.validateFile(file, ['image/jpeg', 'image/png', 'image/webp'], 2 * 1024 * 1024);
                    if (err) {
                        event.target.value = '';
                        return ui.showModal('Archivo Inválido', err);
                    }
                    ui.avatarFileStore = file;
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        ui.avatarBase64Store = e.target.result;
                        const target = document.getElementById(targetImgId);
                        if (target) target.src = ui.avatarBase64Store;
                    };
                    reader.readAsDataURL(file);
                }
            },

            clearAvatarStore: () => {
                ui.avatarBase64Store = null;
                ui.avatarFileStore = null;
                if (document.getElementById('u-avatar-preview')) document.getElementById('u-avatar-preview').src = 'https://placehold.co/100x100/e2e8f0/475569?text=+';
                if (document.getElementById('u-avatar-upload')) document.getElementById('u-avatar-upload').value = '';
            },

            openStudentModal: (id = null) => {
                const instId = auth.currentUser.instId;
                const programs = db.get('programs').filter(p => p.instId === instId);
                const progSelect = document.getElementById('std-programa');
                if (progSelect) {
                    progSelect.innerHTML = '<option value="">Seleccione el curso</option>' + programs.map(p => `<option value="${p.id}">${security.esc(p.nombre)}</option>`).join('');
                }

                const inputs = document.querySelectorAll('#student-modal input, #student-modal select');
                inputs.forEach(input => {
                    if (input.id !== 'std-programa' && input.id !== 'std-salon' && input.id !== 'std-horario') input.value = '';
                });

                document.getElementById('std-salon').innerHTML = '<option value="">Seleccione un curso primero</option>';
                if (document.getElementById('std-horario')) document.getElementById('std-horario').innerHTML = '<option value="">Seleccione un curso primero</option>';

                if (id) {
                    document.getElementById('student-modal-title').innerText = 'Editar estudiante';
                    const user = db.get('users').find(u => u.id === id);
                    if (user) {
                        document.getElementById('std-id').value = user.id;
                        const names = user.name.split(' ');
                        document.getElementById('std-nombre1').value = names[0] || '';
                        document.getElementById('std-nombre2').value = names.slice(1).join(' ') || '';

                        const lastNames = (user.lastName || '').split(' ');
                        document.getElementById('std-apellido1').value = lastNames[0] || '';
                        document.getElementById('std-apellido2').value = lastNames.slice(1).join(' ') || '';

                        document.getElementById('std-tipo-doc').value = user.docType || '';
                        document.getElementById('std-doc').value = user.document || '';
                        document.getElementById('std-sexo').value = user.sexo || '';
                        document.getElementById('std-email').value = user.email || '';
                        document.getElementById('std-tel').value = user.tel || '';
                        document.getElementById('std-cel').value = user.cel || '';
                        document.getElementById('std-birth').value = user.birthDate || '';
                        document.getElementById('std-lugar-nac').value = user.lugarNac || '';
                        document.getElementById('std-dir').value = user.dir || '';
                        document.getElementById('std-lugar-res').value = user.lugarRes || '';
                        document.getElementById('std-barrio').value = user.barrio || '';
                        document.getElementById('std-periodo').value = user.periodo || '2026-B';
                        document.getElementById('std-sede').value = user.sede || 'Sede Principal';

                        const assignment = db.get('assignments').find(a => a.studentIds.includes(user.id));
                        if (assignment) {
                            document.getElementById('std-programa').value = assignment.programId;
                            ui.updateStdSalonDropdown();
                            setTimeout(() => {
                                document.getElementById('std-salon').value = assignment.salon;
                                if (user.horario) document.getElementById('std-horario').value = user.horario;
                            }, 50);
                        }
                    }
                } else {
                    document.getElementById('student-modal-title').innerText = 'Registrar estudiante';
                    document.getElementById('std-id').value = '';
                }

                document.getElementById('student-modal').classList.remove('hidden');
            },

            closeStudentModal: () => {
                document.getElementById('student-modal').classList.add('hidden');
            },

            openStaffModal: () => {
                logic.clearUserForm();

                const role = auth.currentUser.role;
                const roleContainer = document.getElementById('role-container');
                let roleHtml = `<label class="block text-xs font-semibold text-slate-700 mb-1.5">Rol</label><select id="u-role" onchange="logic.togglePermissions()" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">`;

                if (role === 'admin') {
                    roleHtml += `<option value="rector">Rector</option>`;
                } else if (role === 'rector') {
                    roleHtml += `<option value="profesor">Profesor</option><option value="coordinador">Coordinador</option>`;
                } else if (role === 'coordinador') {
                    roleHtml += `<option value="profesor">Profesor</option>`;
                }
                roleHtml += `</select>`;
                roleContainer.innerHTML = roleHtml;

                const instContainer = document.getElementById('inst-container');
                if (role === 'admin') {
                    const insts = db.get('institutions');
                    let instOpts = insts.map(i => `<option value="${i.id}">${security.esc(i.name)}</option>`).join('');
                    instContainer.innerHTML = `<label class="block text-xs font-semibold text-slate-700 mb-1.5">Institución</label><select id="u-inst" class="w-full border border-slate-300 focus:border-emerald-500 px-3.5 py-2.5 rounded-xl text-sm outline-none bg-white">${instOpts}</select>`;
                    instContainer.classList.remove('hidden');
                } else {
                    instContainer.innerHTML = '';
                    instContainer.classList.add('hidden');
                }

                document.getElementById('staff-modal').classList.remove('hidden');
                logic.togglePermissions();
            },

            togglePermissions: (existingPerms = []) => {
                const roleEl = document.getElementById('u-role');
                const permContainer = document.getElementById('permissions-container');
                const tbody = document.getElementById('coord-perms-matrix-body');
                if (!roleEl || !permContainer) return;

                if (roleEl.value === 'coordinador') {
                    permContainer.classList.remove('hidden');
                    if (tbody) {
                        tbody.innerHTML = SYSTEM_MODULES.map(m => {
                            const found = (existingPerms || []).find(p => p.module_key === m.key) || {};
                            const isNew = !existingPerms || existingPerms.length === 0;
                            const vChecked = isNew ? true : !!found.can_view;
                            const cChecked = !!found.can_create;
                            const uChecked = !!found.can_update;
                            const dChecked = !!found.can_delete;
                            return `
                                <tr class="hover:bg-slate-50/70">
                                    <td class="py-2.5 px-3 font-semibold text-slate-700">${security.esc(m.label)}</td>
                                    <td class="py-2.5 px-2 text-center"><input type="checkbox" data-mod="${m.key}" data-act="can_view" ${vChecked ? 'checked' : ''} class="w-4 h-4 text-emerald-600 rounded"></td>
                                    <td class="py-2.5 px-2 text-center"><input type="checkbox" data-mod="${m.key}" data-act="can_create" ${cChecked ? 'checked' : ''} class="w-4 h-4 text-emerald-600 rounded"></td>
                                    <td class="py-2.5 px-2 text-center"><input type="checkbox" data-mod="${m.key}" data-act="can_update" ${uChecked ? 'checked' : ''} class="w-4 h-4 text-emerald-600 rounded"></td>
                                    <td class="py-2.5 px-2 text-center"><input type="checkbox" data-mod="${m.key}" data-act="can_delete" ${dChecked ? 'checked' : ''} class="w-4 h-4 text-emerald-600 rounded"></td>
                                </tr>
                            `;
                        }).join('');
                    }
                } else {
                    permContainer.classList.add('hidden');
                }
            },

            collectCoordinatorPermissionsMatrix: () => {
                return SYSTEM_MODULES.map(m => {
                    const getVal = (act) => !!document.querySelector(`#coord-perms-matrix-body input[data-mod="${m.key}"][data-act="${act}"]`)?.checked;
                    return {
                        module_key: m.key,
                        can_view: getVal('can_view'),
                        can_create: getVal('can_create'),
                        can_update: getVal('can_update'),
                        can_delete: getVal('can_delete')
                    };
                });
            },

            closeStaffModal: () => {
                document.getElementById('staff-modal').classList.add('hidden');
            },

            saveStudent: async () => {
                const id = document.getElementById('std-id').value;
                const n1 = document.getElementById('std-nombre1').value.trim();
                const n2 = document.getElementById('std-nombre2').value.trim();
                const a1 = document.getElementById('std-apellido1').value.trim();
                const a2 = document.getElementById('std-apellido2').value.trim();
                const typeDoc = document.getElementById('std-tipo-doc').value;
                const doc = document.getElementById('std-doc').value.trim();
                const sexo = document.getElementById('std-sexo').value;
                const email = document.getElementById('std-email').value.trim();
                const tel = document.getElementById('std-tel').value.trim();
                const cel = document.getElementById('std-cel').value.trim();
                const birth = document.getElementById('std-birth').value;
                const lugarNac = document.getElementById('std-lugar-nac').value.trim();
                const dir = document.getElementById('std-dir').value.trim();
                const lugarRes = document.getElementById('std-lugar-res').value.trim();
                const barrio = document.getElementById('std-barrio').value.trim();
                const periodo = document.getElementById('std-periodo').value;
                const sede = document.getElementById('std-sede').value;
                const progId = document.getElementById('std-programa').value;
                const salon = document.getElementById('std-salon').value;
                const horario = document.getElementById('std-horario') ? document.getElementById('std-horario').value : '';

                if (!n1 || !a1 || !typeDoc || !doc || !sexo || !email || !tel || !cel || !birth || !dir || !lugarRes || !periodo || !sede || !progId || !salon || !horario) {
                    return ui.showModal('Error', 'Por favor complete todos los campos obligatorios (*). Incluyendo Curso, Salón y Horario.');
                }

                let users = db.get('users');
                const name = `${n1} ${n2}`.trim();
                const lastName = `${a1} ${a2}`.trim();

                if (id) {
                    const idx = users.findIndex(u => u.id == id);
                    if (idx > -1) {
                        users[idx] = { ...users[idx], name, lastName, document: doc, docType: typeDoc, sexo, email, tel, cel, birthDate: birth, lugarNac, dir, lugarRes, barrio, periodo, sede, horario };
                        const okUser = await db.set('users', users);
                        if (!okUser) return;

                        const canUpdateAssignments = auth.currentUser.role === 'rector' ||
                            (auth.currentUser.role === 'coordinador' && auth.can('assignments', 'update'));

                        if (canUpdateAssignments) {
                            let assignments = db.get('assignments');
                            assignments = assignments.map(a => {
                                if (a.studentIds.includes(parseInt(id))) {
                                    a.studentIds = a.studentIds.filter(sid => sid !== parseInt(id));
                                }
                                return a;
                            });
                            let assignment = assignments.find(a => a.programId == progId && a.salon === salon);
                            if (assignment) {
                                if (!assignment.studentIds.includes(parseInt(id))) assignment.studentIds.push(parseInt(id));
                            } else {
                                assignments.push({ id: Date.now(), instId: auth.currentUser.instId, programId: parseInt(progId), salon: salon, teacherId: null, studentIds: [parseInt(id)] });
                            }
                            await db.set('assignments', assignments);
                        }

                        logic.closeStudentModal();
                        ui.showModal('Éxito', 'Estudiante actualizado correctamente.');
                        ui.renderStudentDetail(parseInt(id), 'personal', 'basica');
                    }
                } else {
                    if (users.find(u => u.email === email)) return ui.showModal('Error', 'El correo electrónico ya se encuentra registrado.');
                    if (users.find(u => u.document === doc)) return ui.showModal('Error', 'El número de identificación ya se encuentra registrado.');

                    const { data: newStudentId, error: rpcErr } = await supabaseClient.rpc('create_integra_user', {
                        p_inst_id: auth.currentUser.instId,
                        p_role: 'estudiante',
                        p_name: name,
                        p_last_name: lastName,
                        p_document: doc,
                        p_doc_type: typeDoc,
                        p_birth_date: birth,
                        p_lugar_nac: lugarNac,
                        p_sexo: sexo,
                        p_email: email,
                        p_tel: tel,
                        p_cel: cel,
                        p_dir: dir,
                        p_lugar_res: lugarRes,
                        p_barrio: barrio,
                        p_periodo: periodo,
                        p_sede: sede,
                        p_horario: horario,
                        p_avatar: null,
                        p_module_perms: null
                    });

                    if (rpcErr || !newStudentId) {
                        return ui.showModal('Error en Servidor', rpcErr ? rpcErr.message : 'No se pudo registrar el estudiante.');
                    }

                    await supabaseClient.auth.resetPasswordForEmail(email, {
                        redirectTo: window.location.origin + window.location.pathname
                    }).catch(() => {});

                    await db.refreshTable('users');

                    let assignments = db.get('assignments');
                    let assignment = assignments.find(a => a.programId == progId && a.salon === salon);
                    if (assignment) {
                        if (!assignment.studentIds.includes(newStudentId)) assignment.studentIds.push(newStudentId);
                    } else {
                        assignments.push({ id: Date.now(), instId: auth.currentUser.instId, programId: parseInt(progId), salon: salon, teacherId: null, studentIds: [newStudentId] });
                    }
                    await db.set('assignments', assignments);

                    logic.closeStudentModal();
                    ui.showModal('Estudiante Matriculado', `Identidad creada en Supabase Auth y perfil vinculado.\n\nSe envió un correo de activación a ${email} para que el estudiante configure su contraseña personal.`);
                    ui.renderStudentDetail(newStudentId);
                }
            },

            clearUserForm: () => {
                const uId = document.getElementById('u-id');
                if (uId) uId.value = '';
                const uName = document.getElementById('u-name');
                if (uName) uName.value = '';
                const uEmail = document.getElementById('u-email');
                if (uEmail) uEmail.value = '';
                const btnSubmit = document.getElementById('btn-user-submit');
                if (btnSubmit) btnSubmit.innerText = 'Guardar Personal';
                const title = document.getElementById('user-form-title');
                if (title) title.innerText = 'Registrar Personal';
                const resetBox = document.getElementById('staff-reset-pass-container');
                if (resetBox) resetBox.classList.add('hidden');
                logic.clearAvatarStore();
            },

            saveUser: async () => {
                const id = document.getElementById('u-id').value;
                const roleEl = document.getElementById('u-role');
                const role = roleEl ? roleEl.value : 'rector';
                const name = document.getElementById('u-name').value.trim();
                const email = document.getElementById('u-email').value.trim();

                let instId = auth.currentUser.instId;
                if (auth.currentUser.role === 'admin') {
                    const uInstEl = document.getElementById('u-inst');
                    if (!uInstEl || !uInstEl.value) return ui.showModal('Error', 'Debe crear una institución primero.');
                    instId = parseInt(uInstEl.value);
                }

                const modulePerms = (role === 'coordinador' && auth.currentUser.role === 'rector')
                    ? logic.collectCoordinatorPermissionsMatrix()
                    : null;

                if (!name || !email) return ui.showModal('Error', 'Complete nombre y correo.');

                let finalAvatar = ui.avatarBase64Store;
                let avatarStoragePath = null;
                if (ui.avatarFileStore) {
                    const folder = auth.currentUser.authUserId ? `avatars/${auth.currentUser.authUserId}` : 'avatars';
                    const cloudPath = await db.uploadPrivateFile(folder, ui.avatarFileStore);
                    if (cloudPath) {
                        avatarStoragePath = cloudPath;
                        const signed = await db.getSignedFileUrl(cloudPath, 3600);
                        if (signed) finalAvatar = signed;
                    }
                }

                let users = db.get('users');
                if (id) {
                    const index = users.findIndex(u => u.id == id);
                    if (index > -1) {
                        if (users.find(u => u.email === email && u.id != id)) return ui.showModal('Error', 'El correo ya existe.');
                        users[index] = { ...users[index], role, name, email, instId };
                        if (avatarStoragePath) {
                            users[index].avatar = avatarStoragePath;
                        } else if (finalAvatar !== null) {
                            users[index].avatar = finalAvatar;
                        }
                        const ok = await db.set('users', users);
                        if (!ok) return;

                        if (role === 'coordinador' && auth.currentUser.role === 'rector' && modulePerms) {
                            const { error: permErr } = await supabaseClient.rpc('save_coordinator_permissions', {
                                p_coordinator_user_id: parseInt(id),
                                p_module_perms: modulePerms
                            });
                            if (permErr) {
                                return ui.showModal('Error en Permisos', permErr.message);
                            }
                            await db.refreshTable('coordinator_permissions');
                        }

                        if (finalAvatar && users[index].avatar === avatarStoragePath) {
                            users[index].avatar = finalAvatar;
                        }

                        ui.showModal('Éxito', 'Usuario y permisos actualizados en el servidor.');
                        logic.closeStaffModal();
                    }
                } else {
                    if (users.find(u => u.email === email)) return ui.showModal('Error', 'El correo ya existe.');
                    const { data: newUserId, error: rpcErr } = await supabaseClient.rpc('create_integra_user', {
                        p_inst_id: instId,
                        p_role: role,
                        p_name: name,
                        p_last_name: '',
                        p_document: '',
                        p_doc_type: '',
                        p_birth_date: '',
                        p_lugar_nac: '',
                        p_sexo: '',
                        p_email: email,
                        p_tel: '',
                        p_cel: '',
                        p_dir: '',
                        p_lugar_res: '',
                        p_barrio: '',
                        p_periodo: '',
                        p_sede: '',
                        p_horario: '',
                        p_avatar: avatarStoragePath || finalAvatar,
                        p_module_perms: modulePerms
                    });

                    if (rpcErr || !newUserId) {
                        return ui.showModal('Error en Servidor', rpcErr ? rpcErr.message : 'No se pudo registrar el usuario.');
                    }

                    await supabaseClient.auth.resetPasswordForEmail(email, {
                        redirectTo: window.location.origin + window.location.pathname
                    }).catch(() => {});

                    await db.refreshTable('users');
                    if (role === 'coordinador') await db.refreshTable('coordinator_permissions');
                    ui.showModal('Personal Registrado', `Cuenta creada en Supabase Auth para ${email}.\n\nSe ha enviado un enlace de activación a su correo electrónico para que defina su contraseña.`);
                    logic.closeStaffModal();
                }

                logic.clearUserForm();
                chat.refreshUI();
                ui.renderUsers();
            },

            editUser: (id) => {
                const user = db.get('users').find(u => u.id === id);
                if (user) {
                    if (auth.currentUser.role === 'admin' && user.role !== 'rector') {
                        return ui.showModal('Error', 'El Super Administrador solo tiene permisos para gestionar Rectores.');
                    }
                    if (user.role === 'estudiante') {
                        ui.renderStudentDetail(user.id);
                        return;
                    }

                    logic.openStaffModal();
                    document.getElementById('user-form-title').innerText = 'Editar Personal';
                    document.getElementById('u-id').value = user.id;

                    const roleEl = document.getElementById('u-role');
                    if (roleEl) {
                        roleEl.value = user.role;
                        const existingPerms = db.get('coordinator_permissions').filter(p => p.coordinator_user_id === user.id);
                        logic.togglePermissions(existingPerms);
                    }

                    document.getElementById('u-name').value = user.name;
                    document.getElementById('u-email').value = user.email;

                    if (user.avatar) {
                        document.getElementById('u-avatar-preview').src = user.avatar;
                        ui.avatarBase64Store = user.avatar;
                    }

                    if (document.getElementById('u-inst')) document.getElementById('u-inst').value = user.instId;
                    document.getElementById('btn-user-submit').innerText = 'Actualizar Personal';

                    const resetBox = document.getElementById('staff-reset-pass-container');
                    const resetBtn = document.getElementById('btn-staff-reset-pass');
                    if (resetBox && resetBtn) {
                        const meRole = auth.currentUser.role;
                        const canReset = (meRole === 'admin' && user.role === 'rector') ||
                            ((meRole === 'rector' || meRole === 'coordinador') && user.instId === auth.currentUser.instId && user.role !== 'admin' && user.role !== 'rector');
                        if (canReset) {
                            resetBox.classList.remove('hidden');
                            resetBtn.onclick = () => logic.resetUserPassword(user.id);
                        } else {
                            resetBox.classList.add('hidden');
                        }
                    }
                }
            },

            resetUserPassword: async (id) => {
                const target = db.get('users').find(u => u.id === id);
                if (!target || !target.email) {
                    return ui.showModal('Error', 'El usuario no tiene un correo electrónico válido.');
                }

                const { error } = await supabaseClient.auth.resetPasswordForEmail(target.email, {
                    redirectTo: window.location.origin + window.location.pathname
                });

                if (error) {
                    return ui.showModal('Error', error.message);
                }

                ui.showModal(
                    'Enlace de Recuperación Enviado',
                    `Supabase Auth ha enviado un enlace seguro de restablecimiento de contraseña al correo:\n\n${target.email}`
                );
            },

            deleteUser: async (id) => {
                if (id === 1) return ui.showModal('Error', 'No se puede eliminar al Super Administrador del sistema.');
                if (id === auth.currentUser.id) return ui.showModal('Error', 'No puede eliminar su propia cuenta mientras esté en uso.');

                let users = db.get('users');
                const userToDelete = users.find(u => u.id === id);

                if (auth.currentUser.role === 'admin' && userToDelete && userToDelete.role !== 'rector') {
                    return ui.showModal('Error', 'El Super Administrador solo tiene permisos para eliminar Rectores.');
                }
                if (userToDelete && auth.currentUser.role !== 'admin' && userToDelete.instId !== auth.currentUser.instId) {
                    return ui.showModal('Error', 'No tiene permisos para eliminar este usuario de otra institución.');
                }

                users = users.filter(u => u.id !== id);
                const ok = await db.set('users', users);
                if (!ok) return;
                ui.showModal('Éxito', 'Usuario eliminado correctamente del sistema.');
                chat.refreshUI();
                ui.renderUsers();
            },

            showProgramForm: () => {
                document.getElementById('prog-form-container').classList.remove('hidden');
                document.getElementById('prog-form-title').innerText = 'Nuevo Programa';
                document.getElementById('prog-id').value = '';
                document.getElementById('prog-code').value = '';
                document.getElementById('prog-name').value = '';
                document.getElementById('prog-room').value = '';
                if (document.getElementById('prog-jornada')) document.getElementById('prog-jornada').value = 'Mañana';
                if (document.getElementById('prog-matricula')) {
                    document.getElementById('prog-matricula').value = '0';
                    document.getElementById('prog-mensualidad').value = '0';
                    document.getElementById('prog-meses').value = '1';
                    document.getElementById('prog-uniforme').value = '0';
                }
                logic.currentHorarios = [];
                logic.renderHorariosList();
                document.getElementById('prog-code').focus();
            },

            editProgram: (id) => {
                const p = db.get('programs').find(x => x.id === id);
                if (p) {
                    logic.showProgramForm();
                    document.getElementById('prog-form-title').innerText = 'Editar Programa';
                    document.getElementById('prog-id').value = p.id;
                    document.getElementById('prog-code').value = p.code || '';
                    document.getElementById('prog-name').value = p.nombre;
                    document.getElementById('prog-cal').value = p.calendario;
                    document.getElementById('prog-year').value = p['año'];
                    if (document.getElementById('prog-jornada')) document.getElementById('prog-jornada').value = p.jornada || 'Mañana';
                    document.getElementById('prog-room').value = p.salones ? p.salones.join(', ') : '';
                    if (document.getElementById('prog-matricula')) {
                        document.getElementById('prog-matricula').value = p.costMatricula || '0';
                        document.getElementById('prog-mensualidad').value = p.costMensualidad || '0';
                        document.getElementById('prog-meses').value = p.durationMeses || '1';
                        document.getElementById('prog-uniforme').value = p.costUniforme || '0';
                    }
                    logic.currentHorarios = p.horarios ? [...p.horarios] : (p.horario ? [{ id: Date.now(), texto: p.horario }] : []);
                    logic.renderHorariosList();
                }
            },

            saveProgram: async () => {
                const id = document.getElementById('prog-id').value;
                const code = document.getElementById('prog-code').value.trim();
                const nombre = document.getElementById('prog-name').value.trim();
                const calendario = document.getElementById('prog-cal').value;
                const año = document.getElementById('prog-year').value;
                const jornada = document.getElementById('prog-jornada') ? document.getElementById('prog-jornada').value : 'Mañana';
                const salonInput = document.getElementById('prog-room').value.trim();
                const costMatricula = document.getElementById('prog-matricula')?.value || '0';
                const costMensualidad = document.getElementById('prog-mensualidad')?.value || '0';
                const durationMeses = document.getElementById('prog-meses')?.value || '1';
                const costUniforme = document.getElementById('prog-uniforme')?.value || '0';

                if (!nombre || !año || !salonInput) return ui.showModal('Error', 'Debe diligenciar Nombre, Año y Salón(es).');
                if (logic.currentHorarios.length === 0) return ui.showModal('Error', 'Debe agregar al menos un horario (días y horas) para el programa.');

                let programs = db.get('programs');
                const salones = salonInput.split(',').map(s => s.trim()).filter(s => s);

                if (id) {
                    const idx = programs.findIndex(x => x.id == id);
                    if (idx > -1) {
                        programs[idx] = { ...programs[idx], code, nombre, calendario, 'año': año, jornada, horarios: logic.currentHorarios, salones, costMatricula, costMensualidad, durationMeses, costUniforme };
                    }
                } else {
                    const defaultCierre = `${año}-12-31`;
                    programs.push({
                        id: Date.now(), instId: auth.currentUser.instId, code, nombre, calendario, 'año': año, jornada,
                        horarios: logic.currentHorarios, salones, modulos: [],
                        costMatricula, costMensualidad, durationMeses, costUniforme, fechaCierre: defaultCierre
                    });
                }

                const ok = await db.set('programs', programs);
                if (!ok) return;
                document.getElementById('prog-form-container').classList.add('hidden');
                ui.showModal('Éxito', id ? 'Programa actualizado correctamente.' : 'Programa creado correctamente.');
                ui.performProgSearch();
            },

            updateProgramDate: async (progId, newDate) => {
                const programs = db.get('programs');
                const p = programs.find(x => x.id === progId);
                if (p) {
                    p.fechaCierre = newDate;
                    const ok = await db.set('programs', programs);
                    if (!ok) return;
                    ui.showModal('Éxito', 'Fecha de cierre actualizada.');
                    ui.performProgSearch();
                }
            },

            deleteProgram: async (id) => {
                let programs = db.get('programs');
                const assignments = db.get('assignments').filter(a => a.programId === id);
                const hasStudents = assignments.some(a => a.studentIds.length > 0);
                const hasGrades = db.get('grades').some(g => g.programId === id);

                if (hasStudents || hasGrades) {
                    return ui.showModal('Acción Denegada', 'No se puede eliminar este programa porque ya tiene estudiantes matriculados o notas registradas.');
                }

                let allAssignments = db.get('assignments').filter(a => a.programId !== id);
                await db.set('assignments', allAssignments);
                programs = programs.filter(p => p.id !== id);
                const ok = await db.set('programs', programs);
                if (!ok) return;

                ui.performProgSearch();
                ui.showModal('Eliminado', 'Programa eliminado correctamente del sistema.');
            },

            showAssignForm: () => {
                document.getElementById('assign-form-container').classList.remove('hidden');
                document.getElementById('assign-form-title').innerText = 'Asignar Profesor y Estudiantes';
                document.getElementById('assign-prog').value = '';
                document.getElementById('assign-salon').innerHTML = '<option value="">Seleccione un curso primero</option>';
                document.getElementById('assign-teacher').value = '';
                document.querySelectorAll('input[name="assign-students"]').forEach(cb => cb.checked = false);
            },

            editAssignment: (id) => {
                const assignment = db.get('assignments').find(a => a.id === id);
                if (assignment) {
                    logic.showAssignForm();
                    document.getElementById('assign-form-title').innerText = 'Editar Asignación (Agregar/Quitar Estudiantes)';
                    document.getElementById('assign-prog').value = assignment.programId;
                    ui.updateAssignSalonDropdown();
                    setTimeout(() => {
                        document.getElementById('assign-salon').value = assignment.salon;
                        ui.updateAssignStudents();
                        setTimeout(() => {
                            document.getElementById('assign-teacher').value = assignment.teacherId || '';
                            assignment.studentIds.forEach(stId => {
                                const cb = document.querySelector(`input[name="assign-students"][value="${stId}"]`);
                                if (cb) cb.checked = true;
                            });
                        }, 30);
                    }, 30);
                }
            },

            saveAssignment: async () => {
                const programId = parseInt(document.getElementById('assign-prog').value);
                const salon = document.getElementById('assign-salon').value;
                const teacherId = document.getElementById('assign-teacher').value ? parseInt(document.getElementById('assign-teacher').value) : null;
                const studentCheckboxes = document.querySelectorAll('input[name="assign-students"]:checked');
                const studentIds = Array.from(studentCheckboxes).map(cb => parseInt(cb.value));

                if (!programId || !salon) return ui.showModal('Error', 'Seleccione el Curso y el Salón.');
                if (studentIds.length === 0) return ui.showModal('Error', 'Seleccione al menos un estudiante.');

                let assignments = db.get('assignments');
                const existingIndex = assignments.findIndex(a => a.programId === programId && a.salon === salon);
                if (existingIndex > -1) {
                    assignments[existingIndex] = { ...assignments[existingIndex], teacherId, studentIds };
                } else {
                    assignments.push({ id: Date.now(), instId: auth.currentUser.instId, programId, salon, teacherId, studentIds });
                }

                const ok = await db.set('assignments', assignments);
                if (!ok) return;
                ui.showModal('Éxito', 'Asignación guardada para el salón ' + salon + '.');
                ui.renderAssignments();
            },

            deleteAssignment: async (id) => {
                let assignments = db.get('assignments');
                assignments = assignments.filter(a => a.id !== id);
                const ok = await db.set('assignments', assignments);
                if (!ok) return;
                ui.renderAssignments();
                ui.showModal('Eliminado', 'Asignación removida.');
            },

            saveStudentPaymentProfile: async (studentId) => {
                const desc = document.getElementById('prof-pay-desc').value.trim();
                const amount = parseFloat(document.getElementById('prof-pay-amount').value);
                if (!desc || !amount || isNaN(amount) || amount <= 0) {
                    return ui.showModal('Error', 'Debe ingresar un concepto válido y un valor mayor a cero.');
                }

                const records = db.get('accounting');
                const ref = 'REC-' + Math.floor(100000 + Math.random() * 900000);
                records.push({
                    id: Date.now(), instId: auth.currentUser.instId, studentId,
                    date: new Date().toISOString().split('T')[0], type: 'ingreso', amount, desc, ref
                });
                const ok = await db.set('accounting', records);
                if (ok) ui.renderStudentDetail(studentId, 'financiera');
            },

            clearAccountingForm: () => {
                document.getElementById('acc-id').value = '';
                document.getElementById('acc-date').value = new Date().toISOString().split('T')[0];
                document.getElementById('acc-type').value = 'ingreso';
                document.getElementById('acc-amount').value = '';
                document.getElementById('acc-desc').value = '';
                document.getElementById('acc-form-title').innerHTML = '<i class="ph-fill ph-bank mr-1.5 text-emerald-600"></i> Registrar Gastos e Ingresos Generales';
                document.getElementById('btn-save-acc').innerText = 'Registrar Movimiento';
                document.getElementById('btn-cancel-acc').classList.add('hidden');
            },

            editAccounting: (id) => {
                const record = db.get('accounting').find(r => r.id === id);
                if (record) {
                    document.getElementById('acc-id').value = record.id;
                    document.getElementById('acc-date').value = record.date;
                    document.getElementById('acc-type').value = record.type;
                    document.getElementById('acc-amount').value = record.amount;
                    document.getElementById('acc-desc').value = record.desc;
                    document.getElementById('acc-form-title').innerHTML = '<i class="ph-fill ph-pencil-simple mr-1.5 text-amber-600"></i> Editar Movimiento Financiero';
                    document.getElementById('btn-save-acc').innerText = 'Actualizar Movimiento';
                    document.getElementById('btn-cancel-acc').classList.remove('hidden');
                }
            },

            deleteAccounting: async (id) => {
                let records = db.get('accounting').filter(r => r.id !== id);
                const ok = await db.set('accounting', records);
                if (!ok) return;
                ui.renderAccounting();
                ui.showModal('Eliminado', 'Movimiento eliminado correctamente.');
            },

            saveAccounting: async () => {
                const id = document.getElementById('acc-id').value;
                const date = document.getElementById('acc-date').value;
                const type = document.getElementById('acc-type').value;
                const amount = parseFloat(document.getElementById('acc-amount').value);
                const desc = document.getElementById('acc-desc').value.trim();

                if (!date || !amount || !desc) return ui.showModal('Error', 'Complete todos los campos del movimiento.');

                const records = db.get('accounting');
                if (id) {
                    const idx = records.findIndex(r => r.id == id);
                    if (idx > -1) {
                        records[idx] = { ...records[idx], date, type, amount, desc };
                        const ok = await db.set('accounting', records);
                        if (!ok) return;
                        ui.showModal('Éxito', 'Movimiento actualizado correctamente.');
                    }
                } else {
                    records.push({ id: Date.now(), instId: auth.currentUser.instId, date, type, amount, desc });
                    const ok = await db.set('accounting', records);
                    if (!ok) return;
                    ui.showModal('Éxito', 'Movimiento registrado correctamente.');
                }

                logic.clearAccountingForm();
                ui.renderAccounting();
            },

            updateProfile: async () => {
                const user = auth.currentUser;
                const name = document.getElementById('prof-name').value.trim();
                let lastName = user.lastName;
                let birthDate = user.birthDate;

                if (user.role === 'estudiante') {
                    lastName = document.getElementById('prof-lastname').value.trim();
                    birthDate = document.getElementById('prof-birth').value;
                    if (!name || !lastName) return ui.showModal('Error', 'Tus Nombres y Apellidos son obligatorios.');
                } else {
                    if (!name) return ui.showModal('Error', 'El nombre es obligatorio.');
                }

                const currPass = document.getElementById('prof-pass-current')?.value || '';
                const newPass = document.getElementById('prof-pass-new')?.value || '';
                const confirmPass = document.getElementById('prof-pass-confirm')?.value || '';
                let passwordChanged = false;

                if (currPass || newPass || confirmPass) {
                    if (!currPass) {
                        return ui.showModal('Error', 'Debes ingresar tu contraseña actual para cambiarla.');
                    }
                    if (newPass !== confirmPass) {
                        return ui.showModal('Error', 'La nueva contraseña y su confirmación no coinciden.');
                    }
                    const strengthErr = security.validateStrongPassword(newPass);
                    if (strengthErr) {
                        return ui.showModal('Contraseña Débil', strengthErr);
                    }

                    const { error: reauthErr } = await supabaseClient.auth.signInWithPassword({
                        email: user.email,
                        password: currPass
                    });
                    if (reauthErr) {
                        return ui.showModal('Error de Seguridad', 'La contraseña actual es incorrecta.');
                    }

                    const { error: pwdErr } = await supabaseClient.auth.updateUser({ password: newPass });
                    if (pwdErr) {
                        return ui.showModal('Error de Seguridad', pwdErr.message);
                    }
                    passwordChanged = true;
                }

                let finalAvatar = ui.avatarBase64Store;
                let avatarStoragePath = null;
                if (ui.avatarFileStore) {
                    const folder = auth.currentUser.authUserId ? `avatars/${auth.currentUser.authUserId}` : 'avatars';
                    const cloudPath = await db.uploadPrivateFile(folder, ui.avatarFileStore);
                    if (cloudPath) {
                        avatarStoragePath = cloudPath;
                        const signed = await db.getSignedFileUrl(cloudPath, 3600);
                        if (signed) finalAvatar = signed;
                    }
                    ui.avatarFileStore = null;
                }

                let users = db.get('users');
                const index = users.findIndex(u => u.id === user.id);
                if (index > -1) {
                    users[index].name = name;
                    users[index].lastName = lastName;
                    users[index].birthDate = birthDate;
                    if (avatarStoragePath) {
                        users[index].avatar = avatarStoragePath;
                    } else if (finalAvatar) {
                        users[index].avatar = finalAvatar;
                    }

                    const ok = await db.set('users', users);
                    if (!ok) return;

                    if (finalAvatar && users[index].avatar === avatarStoragePath) {
                        users[index].avatar = finalAvatar;
                    }

                    const safeUpdated = security.sanitizeUser(users[index]);
                    auth.currentUser = safeUpdated;

                    const fName = name.split(' ')[0];
                    document.getElementById('header-user-name').innerText = fName;
                    if (safeUpdated.avatar) document.getElementById('header-avatar').src = safeUpdated.avatar;

                    if (document.getElementById('prof-pass-current')) document.getElementById('prof-pass-current').value = '';
                    if (document.getElementById('prof-pass-new')) document.getElementById('prof-pass-new').value = '';
                    if (document.getElementById('prof-pass-confirm')) document.getElementById('prof-pass-confirm').value = '';

                    ui.showModal('Éxito', passwordChanged
                        ? 'Tus datos de perfil y tu nueva contraseña han sido actualizados en Supabase Auth.'
                        : 'Tus datos de perfil han sido actualizados correctamente.');
                }
            },

            downloadMockDoc: async (docId) => {
                const doc = db.get('docs').find(d => d.id === docId);
                if (!doc) return ui.showModal('Error', 'Documento no encontrado o sin autorización.');
                if (!doc.fileUrl) {
                    return ui.showModal('Aviso', `El registro "${doc.fileName}" no tiene un archivo adjunto en el almacenamiento privado.`);
                }
                const signedUrl = await db.getSignedFileUrl(doc.fileUrl, 120);
                if (signedUrl) {
                    window.open(signedUrl, '_blank', 'noopener,noreferrer');
                }
            },

            saveRequiredDoc: async (studentId, desc, fileInput) => {
                if (!fileInput.files.length) return;
                const file = fileInput.files[0];
                const fileErr = security.validateFile(file, ['application/pdf'], 10 * 1024 * 1024);
                if (fileErr) {
                    fileInput.value = '';
                    return ui.showModal('Archivo No Válido', fileErr);
                }
                const filePath = await db.uploadPrivateFile(`inst_${auth.currentUser.instId}/student_${studentId}`, file);
                if (!filePath) return;

                const docs = db.get('docs');
                docs.push({
                    id: Date.now(), instId: auth.currentUser.instId, studentId,
                    fileName: file.name, fileUrl: filePath, desc, uploadDate: new Date().toLocaleDateString('es-ES')
                });
                const ok = await db.set('docs', docs);
                if (ok) ui.renderStudentDetail(studentId, 'personal', 'documentacion');
            },

            saveStudentProfileDoc: async (studentId) => {
                const descInput = document.getElementById('prof-doc-desc');
                const fileInput = document.getElementById('prof-doc-file');
                if (!descInput.value.trim() || !fileInput.files.length) {
                    return ui.showModal('Error', 'Debe ingresar la descripción y seleccionar el archivo PDF.');
                }
                const file = fileInput.files[0];
                const fileErr = security.validateFile(file, ['application/pdf'], 10 * 1024 * 1024);
                if (fileErr) return ui.showModal('Archivo No Válido', fileErr);

                const filePath = await db.uploadPrivateFile(`inst_${auth.currentUser.instId}/student_${studentId}`, file);
                if (!filePath) return;

                const docs = db.get('docs');
                docs.push({
                    id: Date.now(), instId: auth.currentUser.instId, studentId,
                    fileName: file.name, fileUrl: filePath, desc: descInput.value.trim(), uploadDate: new Date().toLocaleDateString('es-ES')
                });
                const ok = await db.set('docs', docs);
                if (ok) ui.renderStudentDetail(studentId, 'personal', 'documentacion');
            },

            deleteStudentProfileDoc: async (docId, studentId) => {
                const targetDoc = db.get('docs').find(d => d.id === docId);
                let docs = db.get('docs').filter(d => d.id !== docId);
                const ok = await db.set('docs', docs);
                if (!ok) return;
                if (targetDoc && targetDoc.fileUrl && !targetDoc.fileUrl.startsWith('http')) {
                    await supabaseClient.storage.from('integra-files').remove([targetDoc.fileUrl]).catch(() => {});
                }
                ui.renderStudentDetail(studentId, 'personal', 'documentacion');
            },

            saveGrade: async () => {
                const assignId = document.getElementById('grade-prog').value;
                const moduleIdVal = document.getElementById('grade-module')?.value || '';
                const studentId = parseInt(document.getElementById('grade-student').value);
                const desc = document.getElementById('grade-desc').value.trim();
                const gradeVal = document.getElementById('grade-val').value;

                if (!assignId || !studentId) return ui.showModal('Error', 'Seleccione Programa y Estudiante.');
                if (!desc || !gradeVal) return ui.showModal('Error', 'Ingrese descripción y calificación.');

                const val = parseFloat(gradeVal);
                if (val < 1.0 || val > 5.0) return ui.showModal('Error', 'La calificación debe estar entre 1.0 y 5.0.');

                const assignment = db.get('assignments').find(a => a.id == assignId);
                const program = db.get('programs').find(p => p.id == assignment.programId);
                if (program && new Date() > new Date(program.fechaCierre)) {
                    return ui.showModal('Error Crítico', 'Este programa está cerrado.');
                }

                const progModules = program && program.modulos ? program.modulos : [];
                if (progModules.length > 0 && !moduleIdVal) {
                    return ui.showModal('Error', 'Seleccione el módulo del programa al que corresponde esta nota.');
                }

                const selectedMod = progModules.find(m => String(m.id) === String(moduleIdVal));

                const grades = db.get('grades');
                grades.push({
                    id: Date.now(),
                    instId: auth.currentUser.instId,
                    programId: program.id,
                    moduleId: selectedMod ? selectedMod.id : null,
                    moduleName: selectedMod ? selectedMod.nombre : 'General',
                    studentId,
                    desc,
                    grade: val.toFixed(1)
                });
                const ok = await db.set('grades', grades);
                if (!ok) return;

                document.getElementById('grade-desc').value = '';
                document.getElementById('grade-val').value = '';
                document.getElementById('grade-desc').focus();
                ui.updateGradesView();
            },

            deleteGrade: async (id) => {
                let grades = db.get('grades');
                const gradeToDelete = grades.find(g => g.id === id);
                if (gradeToDelete) {
                    const program = db.get('programs').find(p => p.id == gradeToDelete.programId);
                    if (program && new Date() > new Date(program.fechaCierre)) {
                        return ui.showModal('Error', 'No puede eliminar notas de un programa cerrado.');
                    }
                    grades = grades.filter(g => g.id !== id);
                    const ok = await db.set('grades', grades);
                    if (!ok) return;
                    ui.updateGradesView();
                }
            },

            saveAttendance: async (assignId, date) => {
                const assignment = db.get('assignments').find(a => a.id == assignId);
                if (!assignment) return;

                const records = [];
                assignment.studentIds.forEach(stId => {
                    const radioChecked = document.querySelector(`input[name="att_${stId}"]:checked`);
                    if (radioChecked) {
                        records.push({ studentId: stId, present: radioChecked.value === 'true' });
                    }
                });

                let attendanceData = db.get('attendance');
                if (attendanceData.find(a => a.programId == assignment.programId && a.salon == assignment.salon && a.date === date)) {
                    return ui.showModal('Error', 'La asistencia para este salón en este día ya fue enviada.');
                }

                attendanceData.push({
                    id: Date.now(), instId: auth.currentUser.instId, programId: assignment.programId, salon: assignment.salon,
                    date, teacherId: auth.currentUser.id, records
                });
                const ok = await db.set('attendance', attendanceData);
                if (!ok) return;
                ui.showModal('Éxito', 'Lista de asistencia enviada y bloqueada.');
                ui.loadAttendanceList();
            }
        };

        // --- 7. INICIALIZACIÓN ---
        window.onload = async () => {
            await db.init();
            await auth.checkSession();

            window.addEventListener('beforeunload', () => {
                if (auth.currentUser) {
                    auth.setOnlineStatus(auth.currentUser.id, false);
                }
            });

            document.addEventListener('click', (e) => {
                if (!e.target.closest('.dropdown') && !e.target.closest('#header-search-container')) {
                    ui.closeAllDropdowns();
                    const searchRes = document.getElementById('global-search-results');
                    if (searchRes) searchRes.classList.add('hidden');
                }
                if (!e.target.closest('#chat-header-widget')) {
                    chat.closeRoster();
                }
            });
        };
