package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type NotificationHandler struct {
	notificationService *services.NotificationService
}

func NewNotificationHandler(notificationService *services.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
	}
}

// 获取通知列表
func (h *NotificationHandler) GetNotifications(c *gin.Context) {
	var req services.NotificationSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "查询参数无效",
		})
		return
	}

	// 如果没有指定用户ID，使用当前用户ID
	if req.UserID == 0 {
		if userID, exists := c.Get("user_id"); exists {
			req.UserID = userID.(uint)
		}
	}

	notifications, total, err := h.notificationService.GetNotifications(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "获取通知列表失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  notifications,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

// 标记通知为已读
func (h *NotificationHandler) MarkAsRead(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的通知ID",
		})
		return
	}

	err = h.notificationService.MarkAsRead(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "标记通知失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "通知已标记为已读",
	})
}

// 删除通知
func (h *NotificationHandler) DeleteNotification(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "无效的通知ID",
		})
		return
	}

	err = h.notificationService.DeleteNotification(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "删除通知失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "通知删除成功",
	})
}

// 获取未读通知数量
func (h *NotificationHandler) GetUnreadCount(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "用户未认证",
		})
		return
	}

	count, err := h.notificationService.GetUnreadCount(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "获取未读通知数量失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"unread_count": count,
	})
}

// 标记所有通知为已读
func (h *NotificationHandler) MarkAllAsRead(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "用户未认证",
		})
		return
	}

	err := h.notificationService.MarkAllAsRead(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "标记所有通知失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "所有通知已标记为已读",
	})
}
