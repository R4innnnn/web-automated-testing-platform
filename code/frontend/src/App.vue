<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'

const moduleOptions = [
  { id: 'sqli', label: 'SQL 注入', detail: '参数对照与数据库错误' },
  { id: 'xss', label: 'XSS', detail: '反射、DOM 与可验证的存储型' },
  { id: 'upload', label: '文件上传', detail: '无害标记文件验证' },
  { id: 'file_include', label: '文件包含／路径遍历', detail: '无害文件签名验证' },
  { id: 'auth', label: '认证安全', detail: '口令、易猜凭证与防猜测' },
  { id: 'info_leak', label: '信息泄漏', detail: '备份与版本库暴露' },
  { id: 'config', label: '配置弱项', detail: 'Cookie、响应头和 CORS' },
  { id: 'open_redirect', label: '开放重定向', detail: '跳转目标验证' },
]
const activeModules = new Set([
  'sqli', 'xss', 'upload', 'file_include', 'auth', 'info_leak', 'open_redirect'
])
const form = reactive({
  mode: 'url',
  url: '',
  source_dir: '',
  startup_mode: 'existing',
  startup_command: '',
  ready_url: '',
  algorithm: 'bfs',
  seed: null,
  max_pages: 20,
  max_requests: 150,
  timeout_seconds: 180,
  request_delay_ms: 300,
  modules: [],
  coverage_report: '',
  log_paths_text: '',
  login: {
    login_url: '', username: '', password: '',
    username_selector: '', password_selector: '',
    submit_selector: '', success_text: '',
    password_change_url: '', test_username: '', test_password: ''
  }
})
const authorization = reactive({
  basis: 'owner', details: '', allowed_origin: '',
  allowed_path_prefix: '/', acknowledged: false
})
const authorizationVisible = ref(false)
const loading = ref(false)
const jobs = ref([])
const selected = ref(null)
let timer = null

const targetUrl = computed(() => form.mode === 'url' ? form.url : form.ready_url)
const isPublic = computed(() => {
  try {
    const host = new URL(targetUrl.value).hostname.toLowerCase().replace(/[\[\]]/g, '')
    if (host === 'localhost' || host.endsWith('.localhost') || host === '::1') return false
    if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) return false
    const m = host.match(/^172\.(\d+)\./)
    if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return false
    return true
  } catch {
    return false
  }
})
const authNeeded = computed(() =>
  isPublic.value && form.modules.some(value => activeModules.has(value))
)
const phaseText = {
  queued: '排队中', running: '运行中', completed: '已完成', failed: '失败',
  starting: '启动目标', source_analysis: '分析源码',
  exploring: '探索页面', probing: '安全检测'
}
const statusText = value => phaseText[value] || value || '未开始'
const severityText = { high: '高', medium: '中', low: '低' }
const result = computed(() => selected.value?.result || {})
const visibleFindings = computed(() =>
  (result.value.findings || []).filter(item => !item.suppressed)
)
const suppressedFindings = computed(() =>
  (result.value.findings || []).filter(item => item.suppressed)
)

function payload() {
  const data = {
    mode: form.mode,
    algorithm: form.algorithm,
    seed: form.seed === null || form.seed === '' ? null : Number(form.seed),
    max_pages: Number(form.max_pages),
    max_requests: Number(form.max_requests),
    timeout_seconds: Number(form.timeout_seconds),
    request_delay_ms: Number(form.request_delay_ms),
    modules: [...form.modules],
  }
  if (form.mode === 'url') data.url = form.url.trim()
  else {
    data.source_dir = form.source_dir.trim()
    data.ready_url = form.ready_url.trim()
    data.startup_mode = form.startup_mode
    if (form.startup_mode === 'command') data.startup_command = form.startup_command.trim()
    if (form.coverage_report.trim()) data.coverage_report = form.coverage_report.trim()
    if (form.log_paths_text.trim()) {
      data.log_paths = form.log_paths_text.split(/[\n,;]/).map(s => s.trim()).filter(Boolean)
    }
  }
  const login = Object.fromEntries(
    Object.entries(form.login).filter(([, value]) => String(value).trim())
  )
  if (Object.keys(login).length) data.login = login
  if (authNeeded.value) data.authorization = { ...authorization }
  return data
}

function validateBasics() {
  if (!targetUrl.value.trim()) {
    ElMessage.warning('请填写目标网址或就绪网址')
    return false
  }
  try {
    const u = new URL(targetUrl.value)
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error()
  } catch {
    ElMessage.warning('目标必须是完整的 http:// 或 https:// 网址')
    return false
  }
  if (form.mode === 'source' && !form.source_dir.trim()) {
    ElMessage.warning('请选择或填写源码目录')
    return false
  }
  return true
}

async function begin() {
  if (!validateBasics()) return
  if (authNeeded.value) {
    try {
      const u = new URL(targetUrl.value)
      authorization.allowed_origin = u.origin
      authorization.allowed_path_prefix = '/'
    } catch {}
    authorizationVisible.value = true
    return
  }
  await createJob()
}

async function createJob() {
  if (authNeeded.value &&
      (!authorization.acknowledged || authorization.details.trim().length < 8)) {
    ElMessage.warning('请填写授权依据并确认测试范围')
    return
  }
  loading.value = true
  try {
    const response = await fetch('/api/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload())
    })
    const data = await response.json()
    if (!response.ok) {
      const message = typeof data.detail === 'string'
        ? data.detail : JSON.stringify(data.detail)
      throw new Error(message)
    }
    authorizationVisible.value = false
    ElMessage.success('任务已创建')
    await refreshJobs()
    await openJob(data.id)
  } catch (error) {
    ElMessage.error(error.message || '创建任务失败')
  } finally {
    loading.value = false
  }
}

async function refreshJobs() {
  try {
    const response = await fetch('/api/jobs')
    if (response.ok) jobs.value = await response.json()
  } catch {}
}

async function openJob(id) {
  try {
    const response = await fetch('/api/jobs/' + encodeURIComponent(id))
    if (response.ok) selected.value = await response.json()
  } catch {}
}

async function poll() {
  await refreshJobs()
  if (selected.value?.id && ['queued', 'running'].includes(selected.value.status)) {
    await openJob(selected.value.id)
  }
}

function reportUrl() {
  return selected.value ? '/api/jobs/' + selected.value.id + '/report' : '#'
}

function screenshotUrl(path) {
  return '/api/jobs/' + selected.value.id + '/artifact/' + path
}

async function markFalsePositive(finding) {
  if (!selected.value) return
  try {
    const response = await fetch(
      '/api/jobs/' + selected.value.id + '/findings/' + finding.id + '/suppress',
      { method: 'POST' }
    )
    if (!response.ok) throw new Error('标记失败')
    await openJob(selected.value.id)
    ElMessage.success('已标记；后续相同目标与发现会自动隐藏')
  } catch (error) {
    ElMessage.error(error.message)
  }
}

async function restoreFinding(finding) {
  if (!selected.value) return
  try {
    const response = await fetch(
      '/api/jobs/' + selected.value.id + '/findings/' + finding.id + '/suppress',
      { method: 'DELETE' }
    )
    if (!response.ok) throw new Error('恢复失败')
    await openJob(selected.value.id)
    ElMessage.success('已恢复发现')
  } catch (error) {
    ElMessage.error(error.message)
  }
}

onMounted(() => {
  poll()
  timer = setInterval(poll, 2000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">W</div>
        <div>
          <strong>Web 自动化测试平台</strong>
          <span>本机运行 · 动态探索 · 可验证证据</span>
        </div>
      </div>
      <div class="topbar-right">
        <span class="online-dot"></span> 本地服务
      </div>
    </header>

    <main class="layout">
      <section class="left-panel">
        <div class="intro">
          <div class="eyebrow">新建任务</div>
          <h1>从目标到证据，<br />一步完成测试。</h1>
          <p>只输入网址即可执行页面探索与错误捕获。安全漏洞检测按需选择。</p>
        </div>

        <div class="panel-card">
          <div class="section-title"><span class="step">01</span><h2>选择目标</h2></div>
          <el-radio-group v-model="form.mode" class="mode-switch">
            <el-radio-button value="url">网址 · 黑盒</el-radio-button>
            <el-radio-button value="source">源码目录 · 白盒＋动态</el-radio-button>
          </el-radio-group>
          <div v-if="form.mode === 'url'" class="field-block">
            <label>目标网址</label>
            <el-input v-model="form.url" placeholder="http://127.0.0.1:8000/" clearable />
            <small>不选安全模块时，直接探索页面并捕获运行错误。</small>
          </div>
          <template v-else>
            <div class="field-block">
              <label>源码目录</label>
              <el-input v-model="form.source_dir" placeholder="D:\project\web-app" clearable />
            </div>
            <div class="field-block">
              <label>启动方式</label>
              <el-radio-group v-model="form.startup_mode">
                <el-radio value="existing">现有服务</el-radio>
                <el-radio value="auto">自动识别</el-radio>
                <el-radio value="command">手动命令</el-radio>
              </el-radio-group>
            </div>
            <div v-if="form.startup_mode === 'command'" class="field-block">
              <label>启动命令</label>
              <el-input v-model="form.startup_command" placeholder="python app.py" />
            </div>
            <div class="field-block">
              <label>就绪网址</label>
              <el-input v-model="form.ready_url" placeholder="http://127.0.0.1:8000/" clearable />
            </div>
            <div class="field-block">
              <label>覆盖率报告（可选）</label>
              <el-input v-model="form.coverage_report" placeholder="coverage.xml / lcov.info / JaCoCo XML" />
            </div>
            <div class="field-block">
              <label>目标日志文件（可选）</label>
              <el-input v-model="form.log_paths_text" placeholder="PHP、Java 或服务器日志路径；多个路径用逗号分隔" />
            </div>
          </template>
        </div>

        <div class="panel-card">
          <div class="section-title"><span class="step">02</span><h2>选择安全检测</h2></div>
          <p class="section-desc">每项独立开启；没有对应入口或证据不足时不会列为发现。</p>
          <el-checkbox-group v-model="form.modules" class="module-grid">
            <el-checkbox v-for="option in moduleOptions" :key="option.id"
              :value="option.id" class="module-option">
              <span class="module-name">{{ option.label }}</span>
              <span class="module-detail">{{ option.detail }}</span>
            </el-checkbox>
          </el-checkbox-group>
          <div v-if="authNeeded" class="risk-hint">
            当前为公开网址，所选模块包含主动探测。启动前需要确认授权与范围。
          </div>
        </div>

        <div class="panel-card">
          <div class="section-title"><span class="step">03</span><h2>运行参数</h2></div>
          <div class="settings-grid">
            <div class="field-block">
              <label>探索算法</label>
              <el-select v-model="form.algorithm">
                <el-option label="广度优先 BFS" value="bfs" />
                <el-option label="深度优先 DFS" value="dfs" />
                <el-option label="随机探索" value="random" />
              </el-select>
            </div>
            <div class="field-block">
              <label>随机种子</label>
              <el-input-number v-model="form.seed" :min="0" controls-position="right" />
            </div>
            <div class="field-block">
              <label>最多页面</label>
              <el-input-number v-model="form.max_pages" :min="1" :max="100" controls-position="right" />
            </div>
            <div class="field-block">
              <label>请求预算</label>
              <el-input-number v-model="form.max_requests" :min="1" :max="1000" controls-position="right" />
            </div>
            <div class="field-block">
              <label>运行上限（秒）</label>
              <el-input-number v-model="form.timeout_seconds" :min="15" :max="1800" controls-position="right" />
            </div>
            <div class="field-block">
              <label>探测间隔（毫秒）</label>
              <el-input-number v-model="form.request_delay_ms" :min="0" :max="10000" controls-position="right" />
            </div>
          </div>
          <el-collapse class="advanced">
            <el-collapse-item title="登录与专用测试账号（可选）" name="login">
              <div class="field-block"><label>登录网址</label><el-input v-model="form.login.login_url" placeholder="http://localhost/login.php" /></div>
              <div class="settings-grid">
                <div class="field-block"><label>登录用户名</label><el-input v-model="form.login.username" /></div>
                <div class="field-block"><label>登录密码</label><el-input v-model="form.login.password" type="password" show-password /></div>
                <div class="field-block"><label>专用测试账号</label><el-input v-model="form.login.test_username" /></div>
                <div class="field-block"><label>专用账号原密码</label><el-input v-model="form.login.test_password" type="password" show-password /></div>
              </div>
              <div class="field-block"><label>修改密码页面（可选）</label><el-input v-model="form.login.password_change_url" /></div>
              <div class="field-block"><label>登录成功特征文字（可选）</label><el-input v-model="form.login.success_text" /></div>
              <small>账号仅用于本次运行；密码不会写入任务记录或报告。认证探测只作用于专用测试账号。</small>
            </el-collapse-item>
          </el-collapse>
        </div>
        <el-button type="primary" size="large" class="start-button" :loading="loading" @click="begin">
          开始测试 <span class="arrow">→</span>
        </el-button>
      </section>

      <section class="right-panel">
        <div class="overview-head">
          <div>
            <div class="eyebrow">运行概览</div>
            <h2>测试进度与发现</h2>
          </div>
          <el-button text @click="refreshJobs">刷新</el-button>
        </div>
        <div v-if="selected" class="job-summary">
          <div class="summary-top">
            <span class="status-pill" :class="selected.status">{{ statusText(selected.status) }}</span>
            <span class="job-id">#{{ selected.id.slice(0, 8) }}</span>
          </div>
          <div class="job-target">{{ selected.target }}</div>
          <div class="metric-row">
            <div><strong>{{ selected.progress?.pages || result.pages?.length || 0 }}</strong><span>页面</span></div>
            <div><strong>{{ selected.progress?.requests || result.request_count || 0 }}</strong><span>请求</span></div>
            <div><strong>{{ selected.progress?.findings ?? visibleFindings.length }}</strong><span>发现</span></div>
          </div>
          <p v-if="selected.status === 'running'" class="phase">正在{{ statusText(selected.progress?.phase) }}…</p>
          <p v-if="selected.error" class="error-box">{{ selected.error }}</p>
          <a v-if="selected.status === 'completed'" :href="reportUrl()" target="_blank" class="report-link">打开完整 HTML 报告 ↗</a>
        </div>
        <div v-else class="empty-current">
          <div class="empty-icon">⌁</div>
          <h3>还没有运行中的任务</h3>
          <p>左侧填写目标，开始后将在这里显示过程和结果。</p>
        </div>

        <template v-if="selected?.status === 'completed'">
          <div class="result-block">
            <div class="result-title"><h3>发现的 Bug</h3><span>{{ visibleFindings.length }} 项</span></div>
            <div v-if="!visibleFindings.length" class="quiet">此次未得到证据充分的错误或漏洞。</div>
            <el-collapse v-else>
              <el-collapse-item v-for="finding in visibleFindings" :key="finding.id"
                :name="finding.id">
                <template #title>
                  <div class="finding-heading">
                    <span class="severity" :class="finding.severity">{{ severityText[finding.severity] || finding.severity }}</span>
                    <strong>{{ finding.title }}</strong>
                  </div>
                </template>
                <div class="finding-detail">
                  <div>{{ finding.url }}</div>
                  <div class="evidence">{{ JSON.stringify(finding.evidence, null, 2) }}</div>
                  <img v-if="finding.screenshot" :src="screenshotUrl(finding.screenshot)" alt="测试截图" />
                  <el-button size="small" text class="false-positive" @click="markFalsePositive(finding)">
                    标记误报
                  </el-button>
                </div>
              </el-collapse-item>
            </el-collapse>
            <div v-if="suppressedFindings.length" class="suppressed-note">
              已标记误报 {{ suppressedFindings.length }} 项，记录仍保留在完整报告中。
              <div v-for="finding in suppressedFindings" :key="finding.id">
                {{ finding.title }}
                <el-button size="small" text @click="restoreFinding(finding)">恢复</el-button>
              </div>
            </div>
          </div>
          <div v-if="result.static_analysis" class="result-block">
            <div class="result-title"><h3>源码分析候选位置</h3><span>{{ result.static_analysis.candidates?.length || 0 }} 处</span></div>
            <p class="quiet">这些位置尚不能单独证明漏洞，供复核动态发现时参考。</p>
            <div class="source-list">
              <div v-for="item in result.static_analysis.candidates?.slice(0, 30)"
                :key="item.file + item.line" class="source-item">
                <span>{{ item.language }}</span>
                <strong>{{ item.file }}:{{ item.line }}</strong>
                <small>{{ item.message }}</small>
              </div>
            </div>
          </div>
          <div v-if="result.coverage" class="result-block">
            <div class="result-title"><h3>覆盖率</h3></div>
            <p>{{ result.coverage.status === 'available' ? result.coverage.line_rate + '% 行覆盖率' : result.coverage.reason }}</p>
          </div>
          <div class="result-block">
            <div class="result-title"><h3>探索时间线</h3><span>{{ result.events?.length || 0 }} 步</span></div>
            <div class="timeline">
              <div v-for="(event, index) in result.events?.slice(0, 40)" :key="index" class="event">
                <span class="event-number">{{ String(index + 1).padStart(2, '0') }}</span>
                <div><strong>{{ event.action }}</strong><small>{{ event.url || event.reason || event.message }}</small></div>
                <span>{{ event.result }}</span>
              </div>
            </div>
          </div>
        </template>

        <div class="history">
          <div class="result-title"><h3>最近任务</h3><span>{{ jobs.length }}</span></div>
          <button v-for="job in jobs" :key="job.id" class="history-item" @click="openJob(job.id)">
            <span class="history-status" :class="job.status"></span>
            <span class="history-target">{{ job.target }}</span>
            <small>{{ statusText(job.status) }}</small>
          </button>
          <div v-if="!jobs.length" class="quiet">暂无任务记录</div>
        </div>
      </section>
    </main>

    <el-dialog v-model="authorizationVisible" title="确认目标授权与测试范围" width="560px">
      <p class="dialog-lead">所选安全模块会向公开网址发送主动探测请求。请仅对你有权测试的目标运行，并填写授权依据。</p>
      <div class="field-block"><label>授权依据类型</label>
        <el-select v-model="authorization.basis">
          <el-option label="我拥有该站点" value="owner" />
          <el-option label="已取得明确书面授权" value="written_permission" />
          <el-option label="公开允许扫描的练习靶场" value="public_lab" />
        </el-select>
      </div>
      <div class="field-block"><label>授权说明或公开规则链接</label>
        <el-input v-model="authorization.details" type="textarea" :rows="3"
          placeholder="说明授权方、允许的测试类型和范围" />
      </div>
      <div class="settings-grid">
        <div class="field-block"><label>允许的站点</label><el-input v-model="authorization.allowed_origin" /></div>
        <div class="field-block"><label>允许的路径前缀</label><el-input v-model="authorization.allowed_path_prefix" /></div>
      </div>
      <el-checkbox v-model="authorization.acknowledged">
        我确认上述范围和依据真实有效，并同意按请求预算执行
      </el-checkbox>
      <template #footer>
        <el-button @click="authorizationVisible = false">返回</el-button>
        <el-button type="primary" :loading="loading" @click="createJob">确认并开始</el-button>
      </template>
    </el-dialog>
  </div>
</template>
