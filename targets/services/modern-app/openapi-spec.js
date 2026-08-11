// 手写 OpenAPI 3.0 规范 —— 仅暴露公开业务端点。
// 注意: /api/internal/health 因开发忘记从文档移除而意外泄露 (线索: 暴露 internal 路径前缀)。
// 真正敏感的内部端点 (/api/internal/config, /api/internal/db-status) 不在文档中。
const OPENAPI_SPEC = {
  openapi: '3.0.3',
  info: {
    title: 'Modern API',
    version: '2.0.0',
    description: '云购商城后端 API — 公开接口文档'
  },
  servers: [
    { url: '/', description: 'current server' }
  ],
  paths: {
    '/api/auth/login': {
      post: {
        summary: '用户登录',
        security: [],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: { type: 'string' },
                  password: { type: 'string' }
                }
              }
            }
          }
        },
        responses: { '200': { description: '登录成功, 返回 JWT' }, '401': { description: '凭据无效' } }
      }
    },
    '/api/auth/register': {
      post: {
        summary: '用户注册',
        security: [],
        responses: { '200': { description: '注册成功, 返回 JWT' } }
      }
    },
    '/api/products': {
      get: {
        summary: '商品列表',
        security: [],
        responses: { '200': { description: '商品列表' } }
      }
    },
    '/shop': {
      get: { summary: '商城首页 (HTML)', security: [], responses: { '200': { description: 'HTML 页面' } } }
    },
    '/community': {
      get: { summary: '社区论坛 (HTML)', security: [], responses: { '200': { description: 'HTML 页面' } } }
    },
    '/support': {
      get: { summary: '客服工单 (HTML)', security: [], responses: { '200': { description: 'HTML 页面' } } }
    },
    '/graphql': {
      post: {
        summary: 'GraphQL 端点',
        security: [],
        responses: { '200': { description: 'GraphQL 响应' } }
      }
    },
    '/api/internal/health': {
      get: {
        summary: '内部健康检查 (开发遗留, 待移除)',
        security: [],
        responses: { '200': { description: '服务健康状态' } }
      }
    }
  }
};

module.exports = OPENAPI_SPEC;
