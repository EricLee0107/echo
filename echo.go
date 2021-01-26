/*
Package echo implements high performance, minimalist Go web framework.

Example:

  package main

  import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
  )

  // Handler
  func hello(c echo.Context) error {
    return c.String(http.StatusOK, "Hello, World!")
  }

  func main() {
    // Echo instance
    e := echo.New()

    // Middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Routes
    e.GET("/", hello)

    // Start server
    e.Logger.Fatal(e.Start(":1323"))
  }

Learn more at https://echo.labstack.com
*/
package echo

import (
	"bytes"
	stdContext "context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	stdLog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/labstack/gommon/color"
	"github.com/labstack/gommon/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type (
	// Echo is the top-level framework instance.
	Echo struct {
		common
		// startupMutex是在服务器配置和启动时锁定Echo实例访问的互斥锁。用于在没有数据竞争的情况下获取侦听器地址信息(哪个接口/端口被侦听器绑定)。
		startupMutex     sync.RWMutex
		StdLogger        *stdLog.Logger
		colorer          *color.Color
		premiddleware    []MiddlewareFunc
		middleware       []MiddlewareFunc
		maxParam         *int		// 最大参数
		router           *Router
		routers          map[string]*Router
		notFoundHandler  HandlerFunc
		pool             sync.Pool
		Server           *http.Server
		TLSServer        *http.Server
		Listener         net.Listener
		TLSListener      net.Listener
		AutoTLSManager   autocert.Manager
		DisableHTTP2     bool
		Debug            bool
		HideBanner       bool
		HidePort         bool
		HTTPErrorHandler HTTPErrorHandler
		Binder           Binder
		Validator        Validator
		Renderer         Renderer
		Logger           Logger
		IPExtractor      IPExtractor
		ListenerNetwork  string
	}

	// Route包含一个处理程序和用于匹配请求的信息。
	Route struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Name   string `json:"name"`
	}

	// HTTPError表示在处理请求时发生的错误。
	HTTPError struct {
		Code     int         `json:"-"`
		Message  interface{} `json:"message"`
		Internal error       `json:"-"` // 存储由外部依赖项返回的错误
	}

	// MiddlewareFunc defines a function to process middleware.
	// MiddlewareFunc定义了一个处理中间件的函数。
	MiddlewareFunc func(HandlerFunc) HandlerFunc

	// HandlerFunc defines a function to serve HTTP requests.
	// HandlerFunc定义了一个用于服务HTTP请求的函数。
	HandlerFunc func(Context) error

	// HTTPErrorHandler is a centralized HTTP error handler.
	// HTTPErrorHandler是一个集中式的HTTP错误处理程序。
	HTTPErrorHandler func(error, Context)

	// Validator is the interface that wraps the Validate function.
	// Validator是包装Validate函数的接口。
	Validator interface {
		Validate(i interface{}) error
	}

	// Renderer is the interface that wraps the Render function.
	// Renderer是封装渲染函数的接口。
	Renderer interface {
		Render(io.Writer, string, interface{}, Context) error
	}

	// Map defines a generic map of type `map[string]interface{}`.
	// Map定义了一个类型为‘Map [string]interface{}’的泛型映射。
	Map map[string]interface{}

	// Common struct for Echo & Group.
	// Echo和Group的通用结构体。
	common struct{}
)

// HTTP methods
// NOTE: Deprecated, please use the stdlib constants directly instead.
const (
	CONNECT = http.MethodConnect
	DELETE  = http.MethodDelete
	GET     = http.MethodGet
	HEAD    = http.MethodHead
	OPTIONS = http.MethodOptions
	PATCH   = http.MethodPatch
	POST    = http.MethodPost
	// PROPFIND = "PROPFIND"
	PUT   = http.MethodPut
	TRACE = http.MethodTrace
)

// MIME types
const (
	MIMEApplicationJSON                  = "application/json"
	MIMEApplicationJSONCharsetUTF8       = MIMEApplicationJSON + "; " + charsetUTF8
	MIMEApplicationJavaScript            = "application/javascript"
	MIMEApplicationJavaScriptCharsetUTF8 = MIMEApplicationJavaScript + "; " + charsetUTF8
	MIMEApplicationXML                   = "application/xml"
	MIMEApplicationXMLCharsetUTF8        = MIMEApplicationXML + "; " + charsetUTF8
	MIMETextXML                          = "text/xml"
	MIMETextXMLCharsetUTF8               = MIMETextXML + "; " + charsetUTF8
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"
	MIMEApplicationProtobuf              = "application/protobuf"
	MIMEApplicationMsgpack               = "application/msgpack"
	MIMETextHTML                         = "text/html"
	MIMETextHTMLCharsetUTF8              = MIMETextHTML + "; " + charsetUTF8
	MIMETextPlain                        = "text/plain"
	MIMETextPlainCharsetUTF8             = MIMETextPlain + "; " + charsetUTF8
	MIMEMultipartForm                    = "multipart/form-data"
	MIMEOctetStream                      = "application/octet-stream"
)

const (
	charsetUTF8 = "charset=UTF-8"
	// PROPFIND Method can be used on collection and property resources.
	PROPFIND = "PROPFIND"
	// REPORT Method can be used to get information about a resource, see rfc 3253
	REPORT = "REPORT"
)

// Headers
const (
	HeaderAccept              = "Accept"
	HeaderAcceptEncoding      = "Accept-Encoding"
	HeaderAllow               = "Allow"
	HeaderAuthorization       = "Authorization"
	HeaderContentDisposition  = "Content-Disposition"
	HeaderContentEncoding     = "Content-Encoding"
	HeaderContentLength       = "Content-Length"
	HeaderContentType         = "Content-Type"
	HeaderCookie              = "Cookie"
	HeaderSetCookie           = "Set-Cookie"
	HeaderIfModifiedSince     = "If-Modified-Since"
	HeaderLastModified        = "Last-Modified"
	HeaderLocation            = "Location"
	HeaderUpgrade             = "Upgrade"
	HeaderVary                = "Vary"
	HeaderWWWAuthenticate     = "WWW-Authenticate"
	HeaderXForwardedFor       = "X-Forwarded-For"
	HeaderXForwardedProto     = "X-Forwarded-Proto"
	HeaderXForwardedProtocol  = "X-Forwarded-Protocol"
	HeaderXForwardedSsl       = "X-Forwarded-Ssl"
	HeaderXUrlScheme          = "X-Url-Scheme"
	HeaderXHTTPMethodOverride = "X-HTTP-Method-Override"
	HeaderXRealIP             = "X-Real-IP"
	HeaderXRequestID          = "X-Request-ID"
	HeaderXRequestedWith      = "X-Requested-With"
	HeaderServer              = "Server"
	HeaderOrigin              = "Origin"

	// Access control
	HeaderAccessControlRequestMethod    = "Access-Control-Request-Method"
	HeaderAccessControlRequestHeaders   = "Access-Control-Request-Headers"
	HeaderAccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods     = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	HeaderAccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	HeaderAccessControlMaxAge           = "Access-Control-Max-Age"

	// Security
	HeaderStrictTransportSecurity         = "Strict-Transport-Security"
	HeaderXContentTypeOptions             = "X-Content-Type-Options"
	HeaderXXSSProtection                  = "X-XSS-Protection"
	HeaderXFrameOptions                   = "X-Frame-Options"
	HeaderContentSecurityPolicy           = "Content-Security-Policy"
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"
	HeaderXCSRFToken                      = "X-CSRF-Token"
	HeaderReferrerPolicy                  = "Referrer-Policy"
)

const (
	// Version of Echo
	Version = "4.1.17"
	website = "https://echo.labstack.com"
	// http://patorjk.com/software/taag/#p=display&f=Small%20Slant&t=Echo
	banner = `
   ____    __
  / __/___/ /  ___
 / _// __/ _ \/ _ \
/___/\__/_//_/\___/ %s
High performance, minimalist Go web framework
%s
____________________________________O/_______
                                    O\
`
)

var (
	methods = [...]string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		PROPFIND,
		http.MethodPut,
		http.MethodTrace,
		REPORT,
	}
)

// Errors
var (
	ErrUnsupportedMediaType        = NewHTTPError(http.StatusUnsupportedMediaType)
	ErrNotFound                    = NewHTTPError(http.StatusNotFound)
	ErrUnauthorized                = NewHTTPError(http.StatusUnauthorized)
	ErrForbidden                   = NewHTTPError(http.StatusForbidden)
	ErrMethodNotAllowed            = NewHTTPError(http.StatusMethodNotAllowed)
	ErrStatusRequestEntityTooLarge = NewHTTPError(http.StatusRequestEntityTooLarge)
	ErrTooManyRequests             = NewHTTPError(http.StatusTooManyRequests)
	ErrBadRequest                  = NewHTTPError(http.StatusBadRequest)
	ErrBadGateway                  = NewHTTPError(http.StatusBadGateway)
	ErrInternalServerError         = NewHTTPError(http.StatusInternalServerError)
	ErrRequestTimeout              = NewHTTPError(http.StatusRequestTimeout)
	ErrServiceUnavailable          = NewHTTPError(http.StatusServiceUnavailable)
	ErrValidatorNotRegistered      = errors.New("validator not registered")
	ErrRendererNotRegistered       = errors.New("renderer not registered")
	ErrInvalidRedirectCode         = errors.New("invalid redirect status code")
	ErrCookieNotFound              = errors.New("cookie not found")
	ErrInvalidCertOrKeyType        = errors.New("invalid cert or key type, must be string or []byte")
	ErrInvalidListenerNetwork      = errors.New("invalid listener network")
)

// Error handlers
var (
	NotFoundHandler = func(c Context) error {
		return ErrNotFound
	}

	MethodNotAllowedHandler = func(c Context) error {
		return ErrMethodNotAllowed
	}
)

// New creates an instance of Echo.
// 具体的获取实例方法
func New() (e *Echo) {
	e = &Echo{
		Server:    new(http.Server), // 创建一个http server 指针
		TLSServer: new(http.Server), // 创建一个https server 指针
		AutoTLSManager: autocert.Manager{
			Prompt: autocert.AcceptTOS,
		},
		// 日志实例
		Logger:          log.New("echo"),
		// 控制台、日志可以彩色输出的实例
		colorer:         color.New(),
		maxParam:        new(int),
		ListenerNetwork: "tcp",
	}
	// http server 绑定实现了server.Handler的实例，也就是说Echo矿建自身实现了http.Handler接口
	e.Server.Handler = e
	// https server 绑定实现了server.Hadnler的实例
	e.TLSServer.Handler = e // 绑定htto服务异常处理的handler
	e.HTTPErrorHandler = e.DefaultHTTPErrorHandler //
	e.Binder = &DefaultBinder{}
	e.Logger.SetLevel(log.ERROR) // 设置日志输出级别
	e.StdLogger = stdLog.New(e.Logger.Output(), e.Logger.Prefix()+": ", 0) // 绑定标准日志输出实例
	// 绑定获取请求上下文实例的闭包
	e.pool.New = func() interface{} {
		return e.NewContext(nil, nil)
	}
	// 绑定路由实例
	e.router = NewRouter(e)
	// 绑定路由map
	// 注意这个属性的含义：路由分租用的，key为host，则按host分租
	// Router.routes存的路由信息（不包含路由的handler)
	e.routers = map[string]*Router{}
	return
}

// NewContext returns a Context instance.
// //返回一个上下文实例。
func (e *Echo) NewContext(r *http.Request, w http.ResponseWriter) Context {
	return &context{
		request:  r,
		response: NewResponse(w, e),
		store:    make(Map),
		echo:     e,
		pvalues:  make([]string, *e.maxParam),
		handler:  NotFoundHandler,
	}
}

// Router returns the default router.
func (e *Echo) Router() *Router {
	return e.router
}

// Routers returns the map of host => router.
func (e *Echo) Routers() map[string]*Router {
	return e.routers
}

// DefaultHTTPErrorHandler is the default HTTP error handler. It sends a JSON response
// with status code.
// DefaultHTTPErrorHandler是默认的HTTP错误处理程序。它发送一个带有状态码的JSON响应
func (e *Echo) DefaultHTTPErrorHandler(err error, c Context) {
	he, ok := err.(*HTTPError)
	if ok {
		if he.Internal != nil {
			if herr, ok := he.Internal.(*HTTPError); ok {
				he = herr
			}
		}
	} else {
		he = &HTTPError{
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}
	}

	// Issue #1426
	code := he.Code
	message := he.Message
	if m, ok := he.Message.(string); ok {
		if e.Debug {
			message = Map{"message": m, "error": err.Error()}
		} else {
			message = Map{"message": m}
		}
	}

	// Send response
	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead { // Issue #608
			err = c.NoContent(he.Code)
		} else {
			err = c.JSON(code, message)
		}
		if err != nil {
			e.Logger.Error(err)
		}
	}
}

// Pre adds middleware to the chain which is run before router.
func (e *Echo) Pre(middleware ...MiddlewareFunc) {
	e.premiddleware = append(e.premiddleware, middleware...)
}

// Use adds middleware to the chain which is run after router.
func (e *Echo) Use(middleware ...MiddlewareFunc) {
	e.middleware = append(e.middleware, middleware...)
}

// CONNECT registers a new CONNECT route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) CONNECT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodConnect, path, h, m...)
}

// DELETE registers a new DELETE route for a path with matching handler in the router
// with optional route-level middleware.
func (e *Echo) DELETE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodDelete, path, h, m...)
}

// GET registers a new GET route for a path with matching handler in the router
// with optional route-level middleware.
func (e *Echo) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodGet, path, h, m...)
}

// HEAD registers a new HEAD route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) HEAD(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodHead, path, h, m...)
}

// OPTIONS registers a new OPTIONS route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) OPTIONS(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodOptions, path, h, m...)
}

// PATCH registers a new PATCH route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) PATCH(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPatch, path, h, m...)
}

// POST registers a new POST route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) POST(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPost, path, h, m...)
}

// PUT registers a new PUT route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) PUT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPut, path, h, m...)
}

// TRACE registers a new TRACE route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Echo) TRACE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodTrace, path, h, m...)
}

// Any registers a new route for all HTTP methods and path with matching handler
// in the router with optional route-level middleware.
func (e *Echo) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = e.Add(m, path, handler, middleware...)
	}
	return routes
}

// Match registers a new route for multiple HTTP methods and path with matching
// handler in the router with optional route-level middleware.
func (e *Echo) Match(methods []string, path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = e.Add(m, path, handler, middleware...)
	}
	return routes
}

// Static registers a new route with path prefix to serve static files from the
// provided root directory.
func (e *Echo) Static(prefix, root string) *Route {
	if root == "" {
		root = "." // For security we want to restrict to CWD.
	}
	return e.static(prefix, root, e.GET)
}

func (common) static(prefix, root string, get func(string, HandlerFunc, ...MiddlewareFunc) *Route) *Route {
	h := func(c Context) error {
		p, err := url.PathUnescape(c.Param("*"))
		if err != nil {
			return err
		}

		name := filepath.Join(root, filepath.Clean("/"+p)) // "/"+ for security
		fi, err := os.Stat(name)
		if err != nil {
			// The access path does not exist
			return NotFoundHandler(c)
		}

		// If the request is for a directory and does not end with "/"
		p = c.Request().URL.Path // path must not be empty.
		if fi.IsDir() && p[len(p)-1] != '/' {
			// Redirect to ends with "/"
			return c.Redirect(http.StatusMovedPermanently, p+"/")
		}
		return c.File(name)
	}
	// Handle added routes based on trailing slash:
	// 	/prefix  => exact route "/prefix" + any route "/prefix/*"
	// 	/prefix/ => only any route "/prefix/*"
	if prefix != "" {
		if prefix[len(prefix)-1] == '/' {
			// Only add any route for intentional trailing slash
			return get(prefix+"*", h)
		}
		get(prefix, h)
	}
	return get(prefix+"/*", h)
}

func (common) file(path, file string, get func(string, HandlerFunc, ...MiddlewareFunc) *Route,
	m ...MiddlewareFunc) *Route {
	return get(path, func(c Context) error {
		return c.File(file)
	}, m...)
}

// File registers a new route with path to serve a static file with optional route-level middleware.
func (e *Echo) File(path, file string, m ...MiddlewareFunc) *Route {
	return e.file(path, file, e.GET, m...)
}

func (e *Echo) add(host, method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	// 获取handler的名称（反射）
	name := handlerName(handler)
	// 寻找当前host的路由实例
	router := e.findRouter(host)
	// 注册路由
	// 注意低三个参数是个闭包 匹配到路由就会执行这个闭包
	router.Add(method, path, func(c Context) error {
		// 初始化一个handler类型的实例
		h := applyMiddleware(handler, middleware...)
		// 执行最后一个中间件
		return h(c)
	})
	// 本次注册进来的路由的信息
	r := &Route{
		Method: method,
		Path:   path,
		Name:   name,
	}
	e.router.routes[method+path] = r
	return r
}

// Add registers a new route for an HTTP method and path with matching handler
// in the router with optional route-level middleware.
func (e *Echo) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	return e.add("", method, path, handler, middleware...)
}

// Host creates a new router group for the provided host and optional host-level middleware.
func (e *Echo) Host(name string, m ...MiddlewareFunc) (g *Group) {
	e.routers[name] = NewRouter(e)
	g = &Group{host: name, echo: e}
	g.Use(m...)
	return
}

// Group creates a new router group with prefix and optional group-level middleware.
func (e *Echo) Group(prefix string, m ...MiddlewareFunc) (g *Group) {
	g = &Group{prefix: prefix, echo: e}
	g.Use(m...)
	return
}

// URI generates a URI from handler.
func (e *Echo) URI(handler HandlerFunc, params ...interface{}) string {
	name := handlerName(handler)
	return e.Reverse(name, params...)
}

// URL is an alias for `URI` function.
func (e *Echo) URL(h HandlerFunc, params ...interface{}) string {
	return e.URI(h, params...)
}

// Reverse generates an URL from route name and provided parameters.
func (e *Echo) Reverse(name string, params ...interface{}) string {
	uri := new(bytes.Buffer)
	ln := len(params)
	n := 0
	for _, r := range e.router.routes {
		if r.Name == name {
			for i, l := 0, len(r.Path); i < l; i++ {
				if (r.Path[i] == ':' || r.Path[i] == '*') && n < ln {
					for ; i < l && r.Path[i] != '/'; i++ {
					}
					uri.WriteString(fmt.Sprintf("%v", params[n]))
					n++
				}
				if i < l {
					uri.WriteByte(r.Path[i])
				}
			}
			break
		}
	}
	return uri.String()
}

// Routes returns the registered routes.
func (e *Echo) Routes() []*Route {
	routes := make([]*Route, 0, len(e.router.routes))
	for _, v := range e.router.routes {
		routes = append(routes, v)
	}
	return routes
}

// AcquireContext returns an empty `Context` instance from the pool.
// You must return the context by calling `ReleaseContext()`.
func (e *Echo) AcquireContext() Context {
	return e.pool.Get().(Context)
}

// ReleaseContext returns the `Context` instance back to the pool.
// You must call it after `AcquireContext()`.
func (e *Echo) ReleaseContext(c Context) {
	e.pool.Put(c)
}

// ServeHTTP implements `http.Handler` interface, which serves HTTP requests.
// ServeHTTP 实现了 http.Handler接口，该接口用于处理HTTP请求
func (e *Echo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 获取context，通过使用对象池实现，降低内存申请和消耗造成的性能损失
	c := e.pool.Get().(*context)
	// 重置上下文
	c.Reset(r, w)
	// 默认handler
	h := NotFoundHandler

	// 没有请求前，需要调用的http中间件
	if e.premiddleware == nil {
		// 先找当前host组的router
		// LCP算法寻找当前path的handler
		e.findRouter(r.Host).Find(r.Method, r.URL.EscapedPath(), c)
		// 找打当前路由的handler
		h = c.Handler()
		// 构成中间件链
		h = applyMiddleware(h, e.middleware...)
	} else {
		h = func(c Context) error {
			e.findRouter(r.Host).Find(r.Method, r.URL.EscapedPath(), c)
			h := c.Handler()
			h = applyMiddleware(h, e.middleware...)
			return h(c)
		}
		h = applyMiddleware(h, e.premiddleware...)
	}

	// 执行中间件链
	// 在applyMiddleware中所有的中间件构成了一个链
	if err := h(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}

	// 释放context
	e.pool.Put(c)
}

// Start starts an HTTP server.
func (e *Echo) Start(address string) error {
	e.startupMutex.Lock()
	// 设置server地址
	e.Server.Addr = address
	if err := e.configureServer(e.Server); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	// 启动server
	return e.serve()
}

// StartTLS starts an HTTPS server.
// If `certFile` or `keyFile` is `string` the values are treated as file paths.
// If `certFile` or `keyFile` is `[]byte` the values are treated as the certificate or key as-is.
func (e *Echo) StartTLS(address string, certFile, keyFile interface{}) (err error) {
	e.startupMutex.Lock()
	var cert []byte
	if cert, err = filepathOrContent(certFile); err != nil {
		e.startupMutex.Unlock()
		return
	}

	var key []byte
	if key, err = filepathOrContent(keyFile); err != nil {
		e.startupMutex.Unlock()
		return
	}

	s := e.TLSServer
	s.TLSConfig = new(tls.Config)
	s.TLSConfig.Certificates = make([]tls.Certificate, 1)
	if s.TLSConfig.Certificates[0], err = tls.X509KeyPair(cert, key); err != nil {
		e.startupMutex.Unlock()
		return
	}

	e.configureTLS(address)
	if err := e.configureServer(s); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	return s.Serve(e.TLSListener)
}

func filepathOrContent(fileOrContent interface{}) (content []byte, err error) {
	switch v := fileOrContent.(type) {
	case string:
		return ioutil.ReadFile(v)
	case []byte:
		return v, nil
	default:
		return nil, ErrInvalidCertOrKeyType
	}
}

// StartAutoTLS starts an HTTPS server using certificates automatically installed from https://letsencrypt.org.
func (e *Echo) StartAutoTLS(address string) error {
	e.startupMutex.Lock()
	s := e.TLSServer
	s.TLSConfig = new(tls.Config)
	s.TLSConfig.GetCertificate = e.AutoTLSManager.GetCertificate
	s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, acme.ALPNProto)

	e.configureTLS(address)
	if err := e.configureServer(s); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	return s.Serve(e.TLSListener)
}

func (e *Echo) configureTLS(address string) {
	s := e.TLSServer
	s.Addr = address
	if !e.DisableHTTP2 {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "h2")
	}
}

// StartServer starts a custom http server.
func (e *Echo) StartServer(s *http.Server) (err error) {
	e.startupMutex.Lock()
	if err := e.configureServer(s); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	return e.serve()
}

func (e *Echo) configureServer(s *http.Server) (err error) {
	// Setup
	e.colorer.SetOutput(e.Logger.Output())
	s.ErrorLog = e.StdLogger
	s.Handler = e
	if e.Debug {
		e.Logger.SetLevel(log.DEBUG)
	}

	if !e.HideBanner {
		e.colorer.Printf(banner, e.colorer.Red("v"+Version), e.colorer.Blue(website))
	}

	if s.TLSConfig == nil {
		if e.Listener == nil {
			e.Listener, err = newListener(s.Addr, e.ListenerNetwork)
			if err != nil {
				return err
			}
		}
		if !e.HidePort {
			e.colorer.Printf("⇨ http server started on %s\n", e.colorer.Green(e.Listener.Addr()))
		}
		return nil
	}
	if e.TLSListener == nil {
		l, err := newListener(s.Addr, e.ListenerNetwork)
		if err != nil {
			return err
		}
		e.TLSListener = tls.NewListener(l, s.TLSConfig)
	}
	if !e.HidePort {
		e.colorer.Printf("⇨ https server started on %s\n", e.colorer.Green(e.TLSListener.Addr()))
	}
	return nil
}

func (e *Echo) serve() error {
	if e.TLSListener != nil {
		return e.Server.Serve(e.TLSListener)
	}
	return e.Server.Serve(e.Listener)
}

// ListenerAddr returns net.Addr for Listener
func (e *Echo) ListenerAddr() net.Addr {
	e.startupMutex.RLock()
	defer e.startupMutex.RUnlock()
	if e.Listener == nil {
		return nil
	}
	return e.Listener.Addr()
}

// TLSListenerAddr returns net.Addr for TLSListener
func (e *Echo) TLSListenerAddr() net.Addr {
	e.startupMutex.RLock()
	defer e.startupMutex.RUnlock()
	if e.TLSListener == nil {
		return nil
	}
	return e.TLSListener.Addr()
}

// StartH2CServer starts a custom http/2 server with h2c (HTTP/2 Cleartext).
func (e *Echo) StartH2CServer(address string, h2s *http2.Server) (err error) {
	e.startupMutex.Lock()
	// Setup
	s := e.Server
	s.Addr = address
	e.colorer.SetOutput(e.Logger.Output())
	s.ErrorLog = e.StdLogger
	s.Handler = h2c.NewHandler(e, h2s)
	if e.Debug {
		e.Logger.SetLevel(log.DEBUG)
	}

	if !e.HideBanner {
		e.colorer.Printf(banner, e.colorer.Red("v"+Version), e.colorer.Blue(website))
	}

	if e.Listener == nil {
		e.Listener, err = newListener(s.Addr, e.ListenerNetwork)
		if err != nil {
			e.startupMutex.Unlock()
			return err
		}
	}
	if !e.HidePort {
		e.colorer.Printf("⇨ http server started on %s\n", e.colorer.Green(e.Listener.Addr()))
	}
	e.startupMutex.Unlock()
	return s.Serve(e.Listener)
}

// Close immediately stops the server.
// It internally calls `http.Server#Close()`.
func (e *Echo) Close() error {
	e.startupMutex.Lock()
	defer e.startupMutex.Unlock()
	if err := e.TLSServer.Close(); err != nil {
		return err
	}
	return e.Server.Close()
}

// Shutdown stops the server gracefully.
// It internally calls `http.Server#Shutdown()`.
func (e *Echo) Shutdown(ctx stdContext.Context) error {
	e.startupMutex.Lock()
	defer e.startupMutex.Unlock()
	if err := e.TLSServer.Shutdown(ctx); err != nil {
		return err
	}
	return e.Server.Shutdown(ctx)
}

// NewHTTPError creates a new HTTPError instance.
func NewHTTPError(code int, message ...interface{}) *HTTPError {
	he := &HTTPError{Code: code, Message: http.StatusText(code)}
	if len(message) > 0 {
		he.Message = message[0]
	}
	return he
}

// Error makes it compatible with `error` interface.
func (he *HTTPError) Error() string {
	if he.Internal == nil {
		return fmt.Sprintf("code=%d, message=%v", he.Code, he.Message)
	}
	return fmt.Sprintf("code=%d, message=%v, internal=%v", he.Code, he.Message, he.Internal)
}

// SetInternal sets error to HTTPError.Internal
func (he *HTTPError) SetInternal(err error) *HTTPError {
	he.Internal = err
	return he
}

// Unwrap satisfies the Go 1.13 error wrapper interface.
func (he *HTTPError) Unwrap() error {
	return he.Internal
}

// WrapHandler wraps `http.Handler` into `echo.HandlerFunc`.
func WrapHandler(h http.Handler) HandlerFunc {
	return func(c Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// WrapMiddleware wraps `func(http.Handler) http.Handler` into `echo.MiddlewareFunc`
func WrapMiddleware(m func(http.Handler) http.Handler) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(c Context) (err error) {
			m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				c.SetResponse(NewResponse(w, c.Echo()))
				err = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return
		}
	}
}

func (e *Echo) findRouter(host string) *Router {
	if len(e.routers) > 0 {
		if r, ok := e.routers[host]; ok {
			return r
		}
	}
	return e.router
}

func handlerName(h HandlerFunc) string {
	t := reflect.ValueOf(h).Type()
	if t.Kind() == reflect.Func {
		return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	}
	return t.String()
}

// // PathUnescape is wraps `url.PathUnescape`
// func PathUnescape(s string) (string, error) {
// 	return url.PathUnescape(s)
// }

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	if c, err = ln.AcceptTCP(); err != nil {
		return
	} else if err = c.(*net.TCPConn).SetKeepAlive(true); err != nil {
		return
	}
	// Ignore error from setting the KeepAlivePeriod as some systems, such as
	// OpenBSD, do not support setting TCP_USER_TIMEOUT on IPPROTO_TCP
	_ = c.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute)
	return
}

func newListener(address, network string) (*tcpKeepAliveListener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrInvalidListenerNetwork
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &tcpKeepAliveListener{l.(*net.TCPListener)}, nil
}

func applyMiddleware(h HandlerFunc, middleware ...MiddlewareFunc) HandlerFunc {
	// 注意这里的中间件是这个路由专属的
	// 而Use、Pre注册的中间件是全局公用的
	// 遍历中间件
	// 注意返回值类型是HandlerFunc
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}
