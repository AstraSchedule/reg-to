package handler

import (
	"fmt"
	"net/http"
	"regexp"
	"reg-to/config"

	"github.com/gin-gonic/gin"
)

var subdomainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func CheckSubdomain(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		subdomain := c.Param("subdomain")

		if !subdomainRegex.MatchString(subdomain) {
			c.JSON(http.StatusBadRequest, gin.H{
				"available": false,
				"message":   "子域名格式不正确，只能包含小写字母、数字和连字符",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"available": true,
			"message":   fmt.Sprintf("%s.getastra.cn 可用", subdomain),
		})
	}
}
