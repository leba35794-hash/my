package main

import (
    "fmt"
    "os"
    "sync"
    "time"
    
    "github.com/gin-gonic/gin"
)

// IP 限流器
type RateLimiter struct {
    visits map[string]*Visitor
    mu     sync.RWMutex
}

type Visitor struct {
    lastSeen      time.Time
    count         int
    coolDownUntil time.Time
    coolDownCount int
}

var limiter = &RateLimiter{
    visits: make(map[string]*Visitor),
}

func (rl *RateLimiter) cleanup() {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    for ip, v := range rl.visits {
        if time.Since(v.lastSeen) > 5*time.Minute {
            delete(rl.visits, ip)
        }
    }
}

func isIPBanned(ip string) bool {
    var banUntil int64
    err := db.QueryRow("SELECT ban_until FROM banned_ips WHERE ip = ? AND ban_until > ?", ip, time.Now().Unix()).Scan(&banUntil)
    return err == nil
}

func banIP(ip string, duration time.Duration, reason string) {
    banUntil := time.Now().Add(duration).Unix()
    db.Exec("INSERT INTO banned_ips (ip, ban_until, reason) VALUES (?, ?, ?)", ip, banUntil, reason)
    writeDetailLog("封禁IP", ip, reason, fmt.Sprintf("封禁时长: %v", duration))
}

func writeDetailLog(action string, ip string, detail string, extra string) {
    os.MkdirAll("./logs", 0755)
    file, err := os.OpenFile("./logs/detail.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer file.Close()
    timestamp := time.Now().Format("2006-01-02 15:04:05.000")
    fmt.Fprintf(file, "[%s] [%s] IP: %s | %s | %s\n", timestamp, action, ip, detail, extra)
}

// 限流中间件
func rateLimitMiddleware() gin.HandlerFunc {
    go func() {
        ticker := time.NewTicker(1 * time.Minute)
        for range ticker.C {
            limiter.cleanup()
            db.Exec("DELETE FROM banned_ips WHERE ban_until <= ?", time.Now().Unix())
        }
    }()
    
    return func(c *gin.Context) {
        ip := c.ClientIP()
        
        if isIPBanned(ip) {
            writeDetailLog("拒绝请求", ip, "IP已被封禁", "")
            c.JSON(403, gin.H{"code": 403, "message": "您已被封禁，请稍后再试"})
            c.Abort()
            return
        }
        
        limiter.mu.Lock()
        defer limiter.mu.Unlock()
        
        now := time.Now()
        v, exists := limiter.visits[ip]
        if !exists {
            limiter.visits[ip] = &Visitor{
                lastSeen: now,
                count:    1,
            }
            c.Next()
            return
        }
        
        v.lastSeen = now
        
        if now.Before(v.coolDownUntil) {
            writeDetailLog("限流", ip, "触发冷静期", fmt.Sprintf("剩余: %v", v.coolDownUntil.Sub(now)))
            c.JSON(429, gin.H{"code": 429, "message": fmt.Sprintf("请求过于频繁，请 %.0f 秒后再试", v.coolDownUntil.Sub(now).Seconds())})
            c.Abort()
            return
        }
        
        if now.Sub(v.lastSeen) > time.Second {
            v.count = 1
            c.Next()
            return
        }
        
        v.count++
        
        if v.count > 20 {
            coolDownDuration := time.Duration(5+v.coolDownCount*2) * time.Second
            if coolDownDuration > 30*time.Second {
                coolDownDuration = 30 * time.Second
            }
            v.coolDownUntil = now.Add(coolDownDuration)
            v.coolDownCount++
            v.count = 0
            
            writeDetailLog("触发冷静期", ip, fmt.Sprintf("请求次数: %d", v.count), fmt.Sprintf("冷静时长: %v, 累计冷静次数: %d", coolDownDuration, v.coolDownCount))
            c.JSON(429, gin.H{"code": 429, "message": fmt.Sprintf("请求过于频繁，请 %.0f 秒后再试", coolDownDuration.Seconds())})
            c.Abort()
            return
        }
        
        if v.coolDownCount >= 5 {
            banIP(ip, 24*time.Hour, fmt.Sprintf("触发冷静期 %d 次", v.coolDownCount))
            delete(limiter.visits, ip)
            writeDetailLog("封禁IP", ip, "冷静次数过多", fmt.Sprintf("累计冷静次数: %d", v.coolDownCount))
            c.JSON(403, gin.H{"code": 403, "message": "请求过于频繁，IP已被封禁24小时"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// 详细日志中间件
func detailLogMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        writeDetailLog("请求开始", c.ClientIP(), fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path), "")
        c.Next()
        duration := time.Since(start)
        status := c.Writer.Status()
        writeDetailLog("请求结束", c.ClientIP(),
            fmt.Sprintf("%s %s -> %d", c.Request.Method, c.Request.URL.Path, status),
            fmt.Sprintf("耗时: %v", duration))
    }
}

// 登录验证中间件
func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        username := c.GetHeader("X-Username")
        token := c.GetHeader("X-Token")
        
        if username == "" || token == "" {
            if c.Request.Method == "GET" {
                c.Redirect(302, "/")
                c.Abort()
                return
            }
            c.JSON(401, gin.H{"code": 401, "message": "未登录"})
            c.Abort()
            return
        }
        
        var dbToken string
        err := db.QueryRow("SELECT session_token FROM users WHERE username = ?", username).Scan(&dbToken)
        if err != nil || token != dbToken {
            c.JSON(401, gin.H{"code": 401, "message": "登录已过期"})
            c.Abort()
            return
        }
        
        c.Set("username", username)
        c.Next()
    }
}
