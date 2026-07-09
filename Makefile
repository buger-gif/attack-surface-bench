.PHONY: help up down verify report test check clean

help:
	@echo "SecpTest Benchmark — 独立靶场 + 标准评测"
	@echo "  make up        拉起靶场"
	@echo "  make down       停止靶场"
	@echo "  make check      健康检查"
	@echo "  make verify     验证 findings"
	@echo "  make report     格式化报告"
	@echo "  make test       单元测试"
	@echo "  make clean      彻底清理"

up:
	docker compose -f targets/docker-compose.yml -p secptest-bm up -d --build
	@sleep 20
	@make check

down:
	docker compose -f targets/docker-compose.yml -p secptest-bm down --remove-orphans

check:
	@echo "=== 靶场健康检查 ==="
	@curl -sf http://www.target.com/ && echo "  www" || echo "  www"
	@curl -sf http://admin.target.com/ && echo "  admin" || echo "  admin"
	@curl -sf http://api.target.com/ && echo "  api" || echo "  api"
	@curl -sf http://shop.target.com/ && echo "  shop" || echo "  shop"
	@curl -sf http://internal.target.com/ && echo "  internal" || echo "  internal"

verify:
	uv run benchmark verify --findings $(FINDINGS) --output $(OUTPUT)

report:
	uv run benchmark report --input $(INPUT) --output $(OUTPUT)

test:
	uv run pytest tests/ -v

clean:
	docker compose -f targets/docker-compose.yml -p secptest-bm down -v --remove-orphans
	docker network rm bm-net 2>/dev/null || true
