#!/usr/bin/env python3
"""Setup script for Honeypot Threat Intelligence Framework

Usage:
    python setup.py              # Minimal setup (API + DB + Worker)
    python setup.py --full       # Full setup (adds Prometheus + Grafana)
    python setup.py --dashboard  # Just dashboard setup

Idempotent - can be run multiple times safely.
"""
import os
import sys
import subprocess
import argparse
from pathlib import Path

def run(cmd: str, check=True):
    """Run shell command"""
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"❌ Error: {result.stderr}")
        sys.exit(1)
    return result

def setup_env():
    """Create .env from template, inject OpenRouter key if available"""
    env_file = Path(".env")
    example = Path(".env.example")
    
    if not example.exists():
        print("❌ .env.example not found")
        sys.exit(1)
    
    # Try to get key from GitHub secrets (via environment)
    api_key = os.getenv("GITHUB_API_KEY_OPENROUTER") or os.getenv("OPENROUTER_API_KEY")
    
    if not env_file.exists():
        env_file.write_text(example.read_text())
        print("  ✓ Created .env from template")
    
    # Inject API key if we have one
    if api_key:
        content = env_file.read_text()
        if "OPENROUTER_API_KEY=" in content and "OPENROUTER_API_KEY=\n" in content:
            content = content.replace("OPENROUTER_API_KEY=\n", f"OPENROUTER_API_KEY={api_key}\n")
            env_file.write_text(content)
            print(f"  ✓ Injected OpenRouter API key")
    
    return True

def setup_git():
    """Ensure clean git state"""
    run("git fetch origin", check=False)
    run("git pull origin main --rebase", check=False)
    
    # Remove any accidentally committed .env
    result = run("git status --porcelain .env 2>/dev/null || echo 'clean'", check=False)
    if ".env" in result.stdout:
        print("  ⚠ .env is tracked - removing from git")
        run("git rm --cached .env || true")
        run("git commit -m 'chore: remove .env from tracking' || true")
    else:
        print("  ✓ .env not tracked")

def setup_docker(full=False):
    """Build and start Docker services"""
    print("\n[Docker Setup]")
    
    # Create necessary volumes
    run("docker volume create honeypot_postgres_data 2>/dev/null || true", check=False)
    run("docker volume create honeypot_cowrie_logs 2>/dev/null || true", check=False)
    
    # Build images
    run("docker compose build --no-cache")
    
    profile = "full" if full else "minimal"
    
    # Start services
    if full:
        run("docker compose --profile full up -d")
    else:
        # Minimal: only core services
        run("docker compose up -d api postgres redis cowrie worker")
    
    print(f"  ✓ Services started ({profile} mode)")

def setup_dashboard():
    """Configure dashboard for public access"""
    print("\n[Dashboard Setup]")
    
    # Update docker-compose for public dashboard port
    compose = Path("docker-compose.yml")
    content = compose.read_text()
    
    # Ensure dashboard port is exposed
    if "9090:9090" not in content:
        print("  ⚠ Prometheus not in docker-compose - add --full flag")
    
    print("  ✓ Dashboard available at http://localhost:8000/dashboard/")

def wait_for_services():
    """Wait for services to be healthy"""
    print("\n[Waiting for services]")
    
    # Wait for API
    import time
    for i in range(30):
        result = run("curl -s http://localhost:8000/health", check=False)
        if result.returncode == 0:
            print("  ✓ API healthy")
            break
        time.sleep(1)
    else:
        print("  ⚠ API may not be ready - check docker-compose logs")

def main():
    parser = argparse.ArgumentParser(description="Setup Honeypot Framework")
    parser.add_argument("--full", action="store_true", help="Include observability stack")
    parser.add_argument("--dashboard", action="store_true", help="Just setup dashboard access")
    args = parser.parse_args()
    
    print("🍯 Honeypot Framework Setup\n")
    
    if args.dashboard:
        setup_dashboard()
        return
    
    # Full setup sequence
    setup_env()
    setup_git()
    setup_docker(full=args.full)
    wait_for_services()
    
    print("\n✅ Setup complete!")
    print("\nEndpoints:")
    print("  API:         http://localhost:8000")
    print("  Dashboard:   http://localhost:8000/dashboard/")
    print("  Cowrie SSH:  localhost:22 (honeypot)")
    if args.full:
        print("  Prometheus:  http://localhost:9090")
        print("  Grafana:     http://localhost:3000")
    
    print("\nDashboard password in .env (default: 'demo')")

if __name__ == "__main__":
    main()