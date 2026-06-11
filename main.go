package main

import (
    "crypto/rand"
    "crypto/subtle"
    "database/sql"
    "encoding/base64"
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"
    
    "github.com/gin-gonic/gin"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/argon2"
)

var db *sql.DB

func main() {
    initDB()
    
    r := gin.Default()
    
    // 全局中间件（顺序很重要）
    r.Use(detailLogMiddleware())  // 先记录日志
    r.Use(rateLimitMiddleware())  // 再限流
    
    // 公开页面
    r.StaticFile("/", "./a.html")
    r.StaticFile("/register.html", "./register.html")
    
    // 保护页面
    protected := r.Group("/")
    protected.Use(authMiddleware())
    {
        protected.StaticFile("/admin.html", "./admin.html")
        protected.StaticFile("/downward.html", "./downward.html")
        protected.StaticFile("/base.apk", "./base.apk")
    }
    
    // 禁止访问
    r.NoRoute(func(c *gin.Context) {
        path := c.Request.URL.Path
        if strings.Contains(path, "data/") || strings.HasSuffix(path, ".db") {
            c.JSON(403, gin.H{"code": 403, "message": "禁止访问"})
            return
        }
        c.JSON(404, gin.H{"code": 404, "message": "页面不存在"})
    })
    
    // 登录接口
    r.POST("/api/login", func(c *gin.Context) {
        username := c.PostForm("username")
        password := c.PostForm("password")
        
        var dbPasswordHash string
        var role string
        err := db.QueryRow("SELECT password_hash, role FROM users WHERE username = ?", username).Scan(&dbPasswordHash, &role)
        
        if err == nil && verifyPassword(password, dbPasswordHash) {
            tokenBytes := make([]byte, 32)
            rand.Read(tokenBytes)
            token := base64.StdEncoding.EncodeToString(tokenBytes)
            
            db.Exec("UPDATE users SET session_token = ? WHERE username = ?", token, username)
            
            if role == "admin" {
                c.JSON(200, gin.H{"code": 0, "message": "登录成功", "redirect": "/admin.html", "token": token, "username": username})
            } else {
                c.JSON(200, gin.H{"code": 0, "message": "登录成功", "redirect": "/downward.html", "token": token, "username": username})
            }
            writeLog("登录成功", username, c.ClientIP())
        } else {
            c.JSON(200, gin.H{"code": 1, "message": "用户名或密码错误"})
            writeLog("登录失败", username, c.ClientIP())
        }
    })
    
    // 注册接口
    r.POST("/api/register", func(c *gin.Context) {
        username := c.PostForm("username")
        password := c.PostForm("password")
        
        if username == "" || password == "" {
            c.JSON(200, gin.H{"code": 1, "message": "账号和密码不能为空"})
            return
        }
        
        var count int
        db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
        
        if count > 0 {
            c.JSON(200, gin.H{"code": 1, "message": "用户名已存在"})
            return
        }
        
        hashedPassword, err := hashPassword(password)
        if err != nil {
            c.JSON(200, gin.H{"code": 1, "message": "注册失败"})
            return
        }
        
        _, err = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')", username, hashedPassword)
        if err != nil {
            c.JSON(200, gin.H{"code": 1, "message": "注册失败"})
            return
        }
        
        c.JSON(200, gin.H{"code": 0, "message": "注册成功"})
        writeLog("注册成功", username, c.ClientIP())
    })
    
    // 评论接口
    r.GET("/api/comments", func(c *gin.Context) {
        rows, err := db.Query(`
            SELECT c.id, c.username, c.content, c.parent_id, c.created_at,
                   COALESCE((SELECT COUNT(*) FROM likes WHERE comment_id = c.id), 0) as like_count
            FROM comments c 
            WHERE c.status = 'approved'
            ORDER BY c.created_at ASC
        `)
        if err != nil {
            c.JSON(200, gin.H{"code": 1, "message": "获取失败", "data": []interface{}{}})
            return
        }
        defer rows.Close()
        
        commentsMap := make(map[int]gin.H)
        var topComments []gin.H
        
        for rows.Next() {
            var id, parentId int
            var username, content, createdAt string
            var likeCount int
            rows.Scan(&id, &username, &content, &parentId, &createdAt, &likeCount)
            
            comment := gin.H{
                "id": id, "username": username, "content": content,
                "parent_id": parentId, "created_at": createdAt, "like_count": likeCount,
                "replies": []gin.H{},
            }
            commentsMap[id] = comment
            
            if parentId == 0 {
                topComments = append(topComments, comment)
            } else {
                if parent, ok := commentsMap[parentId]; ok {
                    replies := parent["replies"].([]gin.H)
                    parent["replies"] = append(replies, comment)
                }
            }
        }
        
        c.JSON(200, gin.H{"code": 0, "data": topComments})
    })
    
    // 发表评论
    r.POST("/api/comments", func(c *gin.Context) {
        username := c.PostForm("username")
        token := c.PostForm("token")
        content := c.PostForm("content")
        parentIdStr := c.PostForm("parent_id")
        
        var dbToken string
        db.QueryRow("SELECT session_token FROM users WHERE username = ?", username).Scan(&dbToken)
        if token != dbToken {
            c.JSON(200, gin.H{"code": 1, "message": "请先登录"})
            return
        }
        
        if username == "" || content == "" {
            c.JSON(200, gin.H{"code": 1, "message": "内容不能为空"})
            return
        }
        
        parentId := 0
        if parentIdStr != "" {
            parentId, _ = strconv.Atoi(parentIdStr)
        }
        
        status := "pending"
        var role string
        db.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
        if role == "admin" {
            status = "approved"
        }
        
        _, err := db.Exec("INSERT INTO comments (username, content, parent_id, status) VALUES (?, ?, ?, ?)", 
            username, content, parentId, status)
        if err != nil {
            c.JSON(200, gin.H{"code": 1, "message": "发表失败"})
            return
        }
        
        if status == "pending" {
            c.JSON(200, gin.H{"code": 0, "message": "评论已提交，等待审核"})
        } else {
            c.JSON(200, gin.H{"code": 0, "message": "评论成功"})
        }
    })
    
    // 点赞
    r.POST("/api/like", func(c *gin.Context) {
        commentIdStr := c.PostForm("comment_id")
        username := c.PostForm("username")
        token := c.PostForm("token")
        
        var dbToken string
        db.QueryRow("SELECT session_token FROM users WHERE username = ?", username).Scan(&dbToken)
        if token != dbToken {
            c.JSON(200, gin.H{"code": 1, "message": "请先登录"})
            return
        }
        
        if commentIdStr == "" || username == "" {
            c.JSON(200, gin.H{"code": 1, "message": "参数错误"})
            return
        }
        
        commentId, _ := strconv.Atoi(commentIdStr)
        
        var count int
        db.QueryRow("SELECT COUNT(*) FROM likes WHERE comment_id = ? AND username = ?", commentId, username).Scan(&count)
        
        if count > 0 {
            db.Exec("DELETE FROM likes WHERE comment_id = ? AND username = ?", commentId, username)
            c.JSON(200, gin.H{"code": 0, "message": "已取消点赞", "action": "unliked"})
        } else {
            db.Exec("INSERT INTO likes (comment_id, username) VALUES (?, ?)", commentId, username)
            c.JSON(200, gin.H{"code": 0, "message": "点赞成功", "action": "liked"})
        }
    })
    
    // 管理员接口
    admin := r.Group("/api/admin")
    admin.Use(func(c *gin.Context) {
        username := c.GetHeader("X-Username")
        token := c.GetHeader("X-Token")
        
        var dbToken, role string
        db.QueryRow("SELECT session_token, role FROM users WHERE username = ?", username).Scan(&dbToken, &role)
        if token != dbToken || role != "admin" {
            c.JSON(403, gin.H{"code": 403, "message": "无权限"})
            c.Abort()
            return
        }
        c.Set("username", username)
        c.Next()
    })
    {
        admin.GET("/pending", func(c *gin.Context) {
            rows, err := db.Query("SELECT id, username, content, parent_id, created_at FROM comments WHERE status = 'pending' ORDER BY created_at DESC")
            if err != nil {
                c.JSON(200, gin.H{"code": 1, "message": "获取失败", "data": []interface{}{}})
                return
            }
            defer rows.Close()
            
            var comments []gin.H
            for rows.Next() {
                var id, parentId int
                var username, content, createdAt string
                rows.Scan(&id, &username, &content, &parentId, &createdAt)
                comments = append(comments, gin.H{
                    "id": id, "username": username, "content": content,
                    "parent_id": parentId, "created_at": createdAt,
                })
            }
            c.JSON(200, gin.H{"code": 0, "data": comments})
        })
        
        admin.POST("/approve", func(c *gin.Context) {
            id := c.PostForm("id")
            action := c.PostForm("action")
            
            if action == "approve" {
                db.Exec("UPDATE comments SET status = 'approved' WHERE id = ?", id)
                c.JSON(200, gin.H{"code": 0, "message": "已通过"})
            } else if action == "delete" {
                db.Exec("DELETE FROM comments WHERE id = ?", id)
                c.JSON(200, gin.H{"code": 0, "message": "已删除"})
            } else {
                c.JSON(200, gin.H{"code": 1, "message": "无效操作"})
            }
        })
        
        admin.GET("/users", func(c *gin.Context) {
            rows, err := db.Query("SELECT id, username, role, created_at FROM users ORDER BY id DESC")
            if err != nil {
                c.JSON(200, gin.H{"code": 1, "message": "获取失败", "data": []interface{}{}})
                return
            }
            defer rows.Close()
            
            var users []gin.H
            for rows.Next() {
                var id int
                var username, role, createdAt string
                rows.Scan(&id, &username, &role, &createdAt)
                users = append(users, gin.H{"id": id, "username": username, "role": role, "created_at": createdAt})
            }
            c.JSON(200, gin.H{"code": 0, "data": users})
        })
        
        // 管理员：查看被封禁的IP
        admin.GET("/banned_ips", func(c *gin.Context) {
            rows, err := db.Query("SELECT ip, ban_until, reason, created_at FROM banned_ips WHERE ban_until > ? ORDER BY ban_until DESC", time.Now().Unix())
            if err != nil {
                c.JSON(200, gin.H{"code": 1, "message": "获取失败", "data": []interface{}{}})
                return
            }
            defer rows.Close()
            
            var ips []gin.H
            for rows.Next() {
                var ip, reason, createdAt string
                var banUntil int64
                rows.Scan(&ip, &banUntil, &reason, &createdAt)
                ips = append(ips, gin.H{
                    "ip": ip, "ban_until": time.Unix(banUntil, 0).Format("2006-01-02 15:04:05"),
                    "reason": reason, "created_at": createdAt,
                })
            }
            c.JSON(200, gin.H{"code": 0, "data": ips})
        })
        
        // 管理员：解封IP
        admin.POST("/unban", func(c *gin.Context) {
            ip := c.PostForm("ip")
            if ip == "" {
                c.JSON(200, gin.H{"code": 1, "message": "IP不能为空"})
                return
            }
            db.Exec("DELETE FROM banned_ips WHERE ip = ?", ip)
            c.JSON(200, gin.H{"code": 0, "message": "已解封"})
        })
    }
    
    fmt.Println("服务器启动在 http://127.0.0.1:5090")
    r.Run("0.0.0.0:5090")
}

// 密码哈希（Argon2id）
func hashPassword(password string) (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }
    
    time := uint32(1)
    memory := uint32(64 * 1024)
    threads := uint8(4)
    keyLen := uint32(32)
    
    hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
    
    encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
        memory, time, threads,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(hash))
    
    return encoded, nil
}

// 验证密码
func verifyPassword(password, encodedHash string) bool {
    parts := strings.Split(encodedHash, "$")
    if len(parts) != 6 {
        return false
    }
    
    var memory, time uint32
    var threads uint8
    fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
    
    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return false
    }
    
    hash, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return false
    }
    
    keyLen := uint32(len(hash))
    newHash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
    
    return subtle.ConstantTimeCompare(hash, newHash) == 1
}

func initDB() {
    var err error
    db, err = sql.Open("sqlite3", "./users.db")
    if err != nil {
        fmt.Println("打开数据库失败:", err)
        return
    }
    
    db.Exec("ALTER TABLE users ADD COLUMN session_token TEXT")
    
    var count int
    db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'root'").Scan(&count)
    if count == 0 {
        hashedPassword, _ := hashPassword("root555")
        db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", "root", hashedPassword)
        fmt.Println("已创建默认管理员: root / root555")
    }
    
    fmt.Println("数据库初始化成功")
}

func writeLog(action string, username string, ip string) {
    os.MkdirAll("./logs", 0755)
    file, err := os.OpenFile("./server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err == nil {
        defer file.Close()
        timestamp := time.Now().Format("2006-01-02 15:04:05")
        fmt.Fprintf(file, "[%s] %s - %s, IP: %s\n", timestamp, action, username, ip)
    }
}
