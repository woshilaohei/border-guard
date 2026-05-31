import { useState, useEffect, useCallback, useRef } from 'react'

// ============================================================
// 类型定义——和behavior.py的to_frontend_data()对齐
// ============================================================
interface ToolCall {
  name: string
  params: Record<string, unknown>
  time: string
}

interface SearchRecord {
  keywords: string
  results: number
}

interface FileOp {
  op: string
  name: string
}

interface SecurityStats {
  blocked: number
  warnings: number
}

interface TokenStats {
  input: number
  output: number
  cost_cny: number
}

interface SessionData {
  session_id: string
  task: string
  duration: string
  tools: ToolCall[]
  searches: SearchRecord[]
  files: FileOp[]
  tokens: TokenStats
  security: SecurityStats
}

interface TodayStats {
  sessions_today: number
  total_tokens: number
  total_cost_cny: number
  total_tool_calls: number
  total_searches: number
  total_blocked: number
}

interface StatusMeta {
  version: string
  saved_at: string
  status_file: string
}

interface FrontendData {
  today: TodayStats
  current_session: SessionData | null
  _meta?: StatusMeta
}

// ============================================================
// Tauri invoke（动态导入，非Tauri环境降级）
// ============================================================
let invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null

async function initTauri() {
  try {
    const tauri = await import('@tauri-apps/api/core')
    invoke = tauri.invoke
    return true
  } catch {
    invoke = null
    return false
  }
}

// ============================================================
// Demo数据（无后端时展示）
// ============================================================
const DEMO_SESSION: SessionData = {
  session_id: '20260601_demo',
  task: 'VSOS Guard Demo',
  duration: '1.5min',
  tools: [
    { name: 'search_web', params: { keywords: 'AI security' }, time: '02:00:01' },
    { name: 'fetch_web', params: { url: 'docs.example.com' }, time: '02:00:15' },
    { name: 'read_file', params: { path: 'guard.py' }, time: '02:00:30' },
    { name: 'write_file', params: { path: 'report.md' }, time: '02:01:01' },
  ],
  searches: [
    { keywords: 'AI agent safety 2026', results: 8 },
    { keywords: 'prompt injection defense', results: 5 },
  ],
  files: [
    { op: 'read', name: 'behavior.py' },
    { op: 'write', name: 'status.json' },
    { op: 'edit', name: 'guard.py' },
  ],
  tokens: { input: 18700, output: 13200, cost_cny: 1.10 },
  security: { blocked: 1, warnings: 0 },
}

const DEMO_TODAY: TodayStats = {
  sessions_today: 3,
  total_tokens: 89500,
  total_cost_cny: 4.72,
  total_tool_calls: 28,
  total_searches: 9,
  total_blocked: 2,
}

// ============================================================
// 安全等级
// ============================================================
type SecurityLevel = 'L3' | 'L2' | 'L1' | 'OFF'
const SECURITY_LEVELS: { key: SecurityLevel; label: string; desc: string; color: string }[] = [
  { key: 'L3', label: 'L3 严格', desc: '全量拦截+递归', color: 'var(--error)' },
  { key: 'L2', label: 'L2 标准', desc: '拦攻击+标记可疑', color: 'var(--warning)' },
  { key: 'L1', label: 'L1 宽松', desc: '只拦明确攻击', color: 'var(--success)' },
  { key: 'OFF', label: '关闭', desc: '停止安全检测', color: 'var(--text-muted)' },
]

// ============================================================
// 监控模式
// ============================================================
type MonitorMode = 'behavior' | 'cost' | 'both' | 'OFF'
const MONITOR_MODES: { key: MonitorMode; label: string; icon: string }[] = [
  { key: 'behavior', label: '行为监控', icon: '🔧' },
  { key: 'cost', label: '算力监控', icon: '💰' },
  { key: 'both', label: '同时监控', icon: '📊' },
  { key: 'OFF', label: '关闭', icon: '⏹' },
]

// ============================================================
// 下拉选择按钮
// ============================================================
function DropdownButton<T extends string>({
  icon,
  label,
  items,
  activeKey,
  onSelect,
  renderItem,
}: {
  icon: string
  label: string
  items: { key: T; label: string }[]
  activeKey: T
  onSelect: (key: T) => void
  renderItem?: (item: { key: T; label: string }) => React.ReactNode
}) {
  const [open, setOpen] = useState(false)

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 12px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          fontSize: '12px',
          fontWeight: 500,
          width: '100%',
          transition: 'background 0.15s',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = 'var(--bg-surface)'
        }}
      >
        <span style={{ fontSize: '14px' }}>{icon}</span>
        <span style={{ flex: 1, textAlign: 'left' }}>{label}</span>
        <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>▾</span>
      </button>
      {open && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            right: 0,
            marginTop: '2px',
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            zIndex: 100,
            overflow: 'hidden',
          }}
        >
          {items.map((item) => (
            <button
              key={item.key}
              onClick={() => {
                onSelect(item.key)
                setOpen(false)
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                width: '100%',
                background: activeKey === item.key ? 'var(--accent-muted)' : 'transparent',
                border: 'none',
                color: activeKey === item.key ? 'var(--accent)' : 'var(--text-primary)',
                cursor: 'pointer',
                fontSize: '12px',
                textAlign: 'left',
                transition: 'background 0.1s',
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background =
                  activeKey === item.key ? 'var(--accent-muted)' : 'var(--bg-hover)')
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.background =
                  activeKey === item.key ? 'var(--accent-muted)' : 'transparent')
              }
            >
              {renderItem ? renderItem(item) : item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ============================================================
// 安全状态面板
// ============================================================
function SecurityPanel({ level, stats }: { level: SecurityLevel; stats: SecurityStats }) {
  const levelInfo = SECURITY_LEVELS.find((l) => l.key === level)!
  return (
    <div style={{ padding: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
        <div
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: levelInfo.color,
            boxShadow: `0 0 6px ${levelInfo.color}`,
          }}
        />
        <span style={{ fontSize: '13px', fontWeight: 600 }}>
          {level === 'OFF' ? 'Security Off' : `Security: ${levelInfo.label}`}
        </span>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: 'auto' }}>
          {levelInfo.desc}
        </span>
      </div>
      <div style={{ display: 'flex', gap: '8px' }}>
        <StatBadge label="Blocked" value={stats.blocked} color="var(--error)" />
        <StatBadge label="Warnings" value={stats.warnings} color="var(--warning)" />
        <StatBadge
          label="Status"
          value={level === 'OFF' ? 'OFF' : 'ON'}
          color={level === 'OFF' ? 'var(--text-muted)' : 'var(--success)'}
        />
      </div>
    </div>
  )
}

// ============================================================
// 行为监控面板
// ============================================================
function BehaviorPanel({
  session,
  monitorMode,
}: {
  session: SessionData | null
  monitorMode: MonitorMode
}) {
  if (!session) {
    return (
      <div style={{ padding: '12px', color: 'var(--text-muted)', fontSize: '12px' }}>
        No active session
      </div>
    )
  }

  return (
    <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {/* 工具调用 */}
      {(monitorMode === 'behavior' || monitorMode === 'both') && session.tools.length > 0 && (
        <Section title="Tool Calls" count={session.tools.length}>
          {session.tools.map((t, i) => (
            <div key={i} style={rowStyle}>
              <span style={{ color: 'var(--accent)', fontWeight: 500 }}>{t.name}</span>
              {t.params && Object.keys(t.params).length > 0 && (
                <span style={{ color: 'var(--text-muted)', fontSize: '11px', marginLeft: '6px' }}>
                  {Object.keys(t.params).join(', ')}
                </span>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* 搜索记录 */}
      {(monitorMode === 'behavior' || monitorMode === 'both') && session.searches.length > 0 && (
        <Section title="Searches" count={session.searches.length}>
          {session.searches.map((s, i) => (
            <div key={i} style={rowStyle}>
              <span style={{ color: 'var(--info)', fontWeight: 500 }}>"{s.keywords}"</span>
              {s.results > 0 && (
                <span style={{ color: 'var(--text-muted)', fontSize: '11px', marginLeft: '6px' }}>
                  {s.results} results
                </span>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* 文件操作 */}
      {(monitorMode === 'behavior' || monitorMode === 'both') && session.files.length > 0 && (
        <Section title="Files" count={session.files.length}>
          {session.files.map((f, i) => (
            <div key={i} style={rowStyle}>
              <span
                style={{
                  color: f.op === 'write' || f.op === 'create' ? 'var(--success)' : 'var(--text-secondary)',
                  fontSize: '11px',
                  width: '36px',
                }}
              >
                {f.op.toUpperCase()}
              </span>
              <span style={{ color: 'var(--text-primary)' }}>{f.name}</span>
            </div>
          ))}
        </Section>
      )}

      {/* 算力统计 */}
      {(monitorMode === 'cost' || monitorMode === 'both') && (
        <Section title="Cost">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={rowStyle}>
              <span style={{ color: 'var(--text-secondary)' }}>Duration</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{session.duration}</span>
            </div>
            <div style={rowStyle}>
              <span style={{ color: 'var(--text-secondary)' }}>Tokens In</span>
              <span style={{ color: 'var(--text-primary)' }}>{session.tokens.input.toLocaleString()}</span>
            </div>
            <div style={rowStyle}>
              <span style={{ color: 'var(--text-secondary)' }}>Tokens Out</span>
              <span style={{ color: 'var(--text-primary)' }}>{session.tokens.output.toLocaleString()}</span>
            </div>
            <div style={{ ...rowStyle, borderTop: '1px solid var(--border-subtle)', paddingTop: '4px', marginTop: '2px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Cost</span>
              <span style={{ color: 'var(--accent)', fontWeight: 600 }}>¥{session.tokens.cost_cny.toFixed(2)}</span>
            </div>
          </div>
        </Section>
      )}
    </div>
  )
}

// ============================================================
// 今日统计栏
// ============================================================
function TodayBar({ today }: { today: TodayStats }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: '6px',
        padding: '10px 12px',
        borderBottom: '1px solid var(--border-subtle)',
        background: 'var(--bg-surface)',
      }}
    >
      <MiniStat label="Sessions" value={today.sessions_today} />
      <MiniStat label="Tokens" value={formatNumber(today.total_tokens)} />
      <MiniStat label="Cost" value={`¥${today.total_cost_cny.toFixed(2)}`} />
      <MiniStat label="Tools" value={today.total_tool_calls} />
      <MiniStat label="Searches" value={today.total_searches} />
      <MiniStat label="Blocked" value={today.total_blocked} color={today.total_blocked > 0 ? 'var(--error)' : undefined} />
    </div>
  )
}

function MiniStat({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '4px 2px',
      }}
    >
      <span style={{ fontSize: '14px', fontWeight: 700, color: color || 'var(--text-primary)' }}>
        {value}
      </span>
      <span style={{ fontSize: '9px', color: 'var(--text-muted)', marginTop: '1px' }}>{label}</span>
    </div>
  )
}

// ============================================================
// 通用小组件
// ============================================================
function StatBadge({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '6px 10px',
        background: 'var(--bg-base)',
        borderRadius: 'var(--radius-sm)',
        flex: 1,
      }}
    >
      <span style={{ fontSize: '16px', fontWeight: 700, color }}>{value}</span>
      <span style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>{label}</span>
    </div>
  )
}

function Section({
  title,
  count,
  children,
}: {
  title: string
  count?: number
  children: React.ReactNode
}) {
  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          marginBottom: '6px',
          paddingBottom: '4px',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          {title}
        </span>
        {count !== undefined && (
          <span
            style={{
              fontSize: '10px',
              color: 'var(--text-muted)',
              background: 'var(--bg-base)',
              padding: '1px 6px',
              borderRadius: '10px',
            }}
          >
            {count}
          </span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>{children}</div>
    </div>
  )
}

const rowStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '4px',
  padding: '2px 4px',
  borderRadius: 'var(--radius-sm)',
  fontSize: '12px',
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toString()
}

// ============================================================
// 连接状态指示器
// ============================================================
type ConnectionStatus = 'connected' | 'demo' | 'loading'

function ConnectionBadge({ status }: { status: ConnectionStatus }) {
  const config = {
    connected: { label: 'LIVE', color: 'var(--success)', bg: 'rgba(52,199,89,0.1)' },
    demo: { label: 'DEMO', color: 'var(--warning)', bg: 'rgba(255,159,10,0.1)' },
    loading: { label: '...', color: 'var(--text-muted)', bg: 'transparent' },
  }[status]

  return (
    <span
      style={{
        fontSize: '9px',
        fontWeight: 700,
        color: config.color,
        background: config.bg,
        padding: '1px 6px',
        borderRadius: '4px',
        letterSpacing: '0.5px',
      }}
    >
      {config.label}
    </span>
  )
}

// ============================================================
// 主App
// ============================================================
function App() {
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>('L2')
  const [monitorMode, setMonitorMode] = useState<MonitorMode>('both')
  const [session, setSession] = useState<SessionData | null>(DEMO_SESSION)
  const [today, setToday] = useState<TodayStats>(DEMO_TODAY)
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('loading')
  const [tauriReady, setTauriReady] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // 初始化Tauri
  useEffect(() => {
    initTauri().then((ok) => {
      setTauriReady(ok)
      if (!ok) {
        setConnectionStatus('demo')
      }
    })
  }, [])

  // 轮询数据
  const fetchData = useCallback(async () => {
    if (!invoke) return
    try {
      const result = await invoke('read_status') as FrontendData
      if (result && result._meta) {
        setSession(result.current_session || null)
        setToday(result.today)
        setConnectionStatus('connected')
      } else {
        setConnectionStatus('demo')
      }
    } catch {
      // 文件不存在或读取失败→Demo模式
      setConnectionStatus('demo')
    }
  }, [])

  useEffect(() => {
    if (!tauriReady) return
    fetchData() // 立即拉一次
    pollRef.current = setInterval(fetchData, 2000) // 每2秒轮询
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [tauriReady, fetchData])

  const activeSecurityLabel =
    SECURITY_LEVELS.find((l) => l.key === securityLevel)?.label || 'L2 标准'
  const activeMonitorLabel =
    MONITOR_MODES.find((m) => m.key === monitorMode)?.label || '同时监控'

  return (
    <div
      style={{
        height: '100vh',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-base)',
      }}
    >
      {/* ===== 顶部控制栏 ===== */}
      <div
        style={{
          display: 'flex',
          gap: '8px',
          padding: '10px 12px',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'var(--bg-surface)',
        }}
      >
        <DropdownButton
          icon="🛡️"
          label={activeSecurityLabel}
          items={SECURITY_LEVELS}
          activeKey={securityLevel}
          onSelect={(key) => setSecurityLevel(key)}
          renderItem={(item) => {
            const info = SECURITY_LEVELS.find((l) => l.key === item.key)!
            return (
              <>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: info.color }} />
                <span>{item.label}</span>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px', marginLeft: 'auto' }}>{info.desc}</span>
              </>
            )
          }}
        />
        <DropdownButton
          icon="📊"
          label={activeMonitorLabel}
          items={MONITOR_MODES}
          activeKey={monitorMode}
          onSelect={(key) => setMonitorMode(key)}
          renderItem={(item) => {
            const info = MONITOR_MODES.find((m) => m.key === item.key)!
            return (
              <>
                <span style={{ fontSize: '13px' }}>{info.icon}</span>
                <span>{item.label}</span>
              </>
            )
          }}
        />
      </div>

      {/* ===== 今日统计 ===== */}
      <TodayBar today={today} />

      {/* ===== 安全状态 ===== */}
      <div style={{ borderBottom: '1px solid var(--border-subtle)' }}>
        <SecurityPanel
          level={securityLevel}
          stats={session?.security || { blocked: 0, warnings: 0 }}
        />
      </div>

      {/* ===== 行为/算力监控 ===== */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <BehaviorPanel session={session} monitorMode={monitorMode} />
      </div>

      {/* ===== 底部状态栏 ===== */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '6px 12px',
          borderTop: '1px solid var(--border-subtle)',
          background: 'var(--bg-surface)',
          fontSize: '11px',
          color: 'var(--text-muted)',
        }}
      >
        <span>VSOS Guard v0.6.0</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <ConnectionBadge status={connectionStatus} />
          <span>{session ? `#${session.session_id.slice(-6)}` : 'No session'}</span>
        </div>
      </div>
    </div>
  )
}

export default App
