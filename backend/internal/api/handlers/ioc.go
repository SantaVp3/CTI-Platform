package handlers

import (
	"net/http"
	"strconv"

	"cti-platform/internal/services"

	"github.com/gin-gonic/gin"
)

type IOCHandler struct {
	iocService *services.IOCService
}

func NewIOCHandler(iocService *services.IOCService) *IOCHandler {
	return &IOCHandler{
		iocService: iocService,
	}
}

func (h *IOCHandler) CreateIOC(c *gin.Context) {
	var req services.CreateIOCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	ioc, err := h.iocService.CreateIOC(req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, ioc)
}

func (h *IOCHandler) GetIOC(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IOC ID",
		})
		return
	}

	ioc, err := h.iocService.GetIOC(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "IOC not found",
		})
		return
	}

	c.JSON(http.StatusOK, ioc)
}

func (h *IOCHandler) UpdateIOC(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IOC ID",
		})
		return
	}

	var req services.UpdateIOCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	userID, _ := c.Get("user_id")
	ioc, err := h.iocService.UpdateIOC(uint(id), req, userID.(uint))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, ioc)
}

func (h *IOCHandler) DeleteIOC(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid IOC ID",
		})
		return
	}

	err = h.iocService.DeleteIOC(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete IOC",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "IOC deleted successfully",
	})
}

func (h *IOCHandler) SearchIOCs(c *gin.Context) {
	var req services.IOCSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid query parameters",
		})
		return
	}

	iocs, total, err := h.iocService.SearchIOCs(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to search IOCs",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  iocs,
		"total": total,
		"page":  req.Page,
		"limit": req.Limit,
	})
}

func (h *IOCHandler) GetIOCTypes(c *gin.Context) {
	types, err := h.iocService.GetIOCTypes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get IOC types",
		})
		return
	}

	c.JSON(http.StatusOK, types)
}
