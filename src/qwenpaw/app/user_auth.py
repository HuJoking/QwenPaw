# -*- coding: utf-8 -*-
"""多用户认证模块：密码哈希、JWT令牌、认证中间件。

扩展原有单用户认证系统，支持：
1. 多用户存储（每个用户独立认证数据）
2. 用户工作区物理隔离
3. 用户级权限控制
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any

from fastapi import Request, Response
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from ..constant import SECRET_DIR, EnvVarLoader, WORKING_DIR
from ..security.secret_store import (
    AUTH_SECRET_FIELDS,
    decrypt_dict_fields,
    encrypt_dict_fields,
    is_encrypted,
)

logger = logging.getLogger(__name__)

# 用户数据目录
USERS_DIR = WORKING_DIR / "local" / "users"
USERS_INDEX_FILE = USERS_DIR / "index.json"

# Token 有效期：7天
TOKEN_EXPIRY_SECONDS = 7 * 24 * 3600

# 公共路径（无需认证）
_PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/api/auth/login",
        "/api/auth/status",
        "/api/auth/register",
        "/api/version",
        "/api/settings/language",
    },
)

# 公共路径前缀
_PUBLIC_PREFIXES: tuple[str, ...] = (
    "/assets/",
    "/logo.png",
    "/qwenpaw-symbol.svg",
)


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------


class UserProfile(BaseModel):
    """用户基本信息"""
    user_id: str = Field(..., description="用户唯一ID")
    username: str = Field(..., description="用户名")
    email: Optional[str] = Field(None, description="邮箱")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_login: Optional[str] = Field(None, description="最后登录时间")
    enabled: bool = Field(True, description="用户是否启用")
    is_admin: bool = Field(False, description="是否为管理员")


class UserAuthData(BaseModel):
    """用户认证数据（加密存储）"""
    user_id: str
    password_hash: str
    password_salt: str
    jwt_secret: str  # 每个用户独立的JWT密钥


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _chmod_best_effort(path, mode: int) -> None:
    """尝试设置文件权限"""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _prepare_secret_parent(path) -> None:
    """创建父目录并设置权限"""
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod_best_effort(path.parent, 0o700)


def _get_user_dir(user_id: str) -> Path:
    """获取用户目录路径"""
    return USERS_DIR / user_id


def _get_user_profile_path(user_id: str) -> Path:
    """获取用户信息文件路径"""
    return _get_user_dir(user_id) / "profile.json"


def _get_user_auth_path(user_id: str) -> Path:
    """获取用户认证文件路径"""
    return _get_user_dir(user_id) / "auth.json"


def _get_user_config_path(user_id: str) -> Path:
    """获取用户配置文件路径"""
    return _get_user_dir(user_id) / "config.json"


def _get_user_workspace_root(user_id: str) -> Path:
    """获取用户工作区根目录"""
    return _get_user_dir(user_id) / "workspaces"


# ---------------------------------------------------------------------------
# 用户索引管理
# ---------------------------------------------------------------------------


def _load_users_index() -> Dict[str, str]:
    """加载用户索引（username -> user_id）"""
    if USERS_INDEX_FILE.exists():
        try:
            with open(USERS_INDEX_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load users index: {e}")
    return {}


def _save_users_index(index: Dict[str, str]) -> None:
    """保存用户索引"""
    _prepare_secret_parent(USERS_INDEX_FILE)
    try:
        with open(USERS_INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)
        _chmod_best_effort(USERS_INDEX_FILE, 0o600)
    except IOError as e:
        logger.error(f"Failed to save users index: {e}")
        raise


def _add_user_to_index(username: str, user_id: str) -> None:
    """添加用户到索引"""
    index = _load_users_index()
    index[username] = user_id
    _save_users_index(index)


def _remove_user_from_index(username: str) -> None:
    """从索引中移除用户"""
    index = _load_users_index()
    index.pop(username, None)
    _save_users_index(index)


def _get_user_id_by_username(username: str) -> Optional[str]:
    """通过用户名查找用户ID"""
    index = _load_users_index()
    return index.get(username)


# ---------------------------------------------------------------------------
# 用户数据加载/保存
# ---------------------------------------------------------------------------


def _load_user_profile(user_id: str) -> Optional[UserProfile]:
    """加载用户信息"""
    profile_path = _get_user_profile_path(user_id)
    if not profile_path.exists():
        return None
    
    try:
        with open(profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return UserProfile(**data)
    except (json.JSONDecodeError, IOError, KeyError) as e:
        logger.error(f"Failed to load user profile {user_id}: {e}")
        return None


def _save_user_profile(profile: UserProfile) -> None:
    """保存用户信息"""
    user_dir = _get_user_dir(profile.user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    
    profile_path = _get_user_profile_path(profile.user_id)
    try:
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile.model_dump(), f, indent=2)
    except IOError as e:
        logger.error(f"Failed to save user profile {profile.user_id}: {e}")
        raise


def _load_user_auth_data(user_id: str) -> Optional[Dict]:
    """加载用户认证数据（加密字段自动解密）"""
    auth_path = _get_user_auth_path(user_id)
    if not auth_path.exists():
        return None
    
    try:
        with open(auth_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 检查是否需要加密
        needs_rewrite = any(
            isinstance(data.get(field), str)
            and data.get(field)
            and not is_encrypted(data[field])
            for field in AUTH_SECRET_FIELDS
        )
        
        # 解密加密字段
        data = decrypt_dict_fields(data, AUTH_SECRET_FIELDS)
        
        if needs_rewrite:
            # 自动重写为加密格式
            _save_user_auth_data(data)
            
        return data
    except (json.JSONDecodeError, IOError, KeyError) as e:
        logger.error(f"Failed to load user auth data {user_id}: {e}")
        return None


def _save_user_auth_data(data: Dict) -> None:
    """保存用户认证数据（自动加密敏感字段）"""
    user_id = data.get("user_id")
    if not user_id:
        raise ValueError("user_id is required")
    
    user_dir = _get_user_dir(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    
    auth_path = _get_user_auth_path(user_id)
    
    # 加密敏感字段
    encrypted_data = encrypt_dict_fields(data, AUTH_SECRET_FIELDS)
    
    _prepare_secret_parent(auth_path)
    try:
        with open(auth_path, "w", encoding="utf-8") as f:
            json.dump(encrypted_data, f, indent=2)
        _chmod_best_effort(auth_path, 0o600)
    except IOError as e:
        logger.error(f"Failed to save user auth data {user_id}: {e}")
        raise


# ---------------------------------------------------------------------------
# 密码哈希
# ---------------------------------------------------------------------------


def _hash_password(
    password: str,
    salt: Optional[str] = None,
) -> Tuple[str, str]:
    """哈希密码，返回 (hash_hex, salt_hex)"""
    if salt is None:
        salt = secrets.token_hex(16)  # 16字节随机盐
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return h, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """验证密码（恒定时间比较）"""
    h, _ = _hash_password(password, salt)
    return hmac.compare_digest(h, stored_hash)


# ---------------------------------------------------------------------------
# JWT令牌管理（每个用户独立密钥）
# ---------------------------------------------------------------------------


def _get_user_jwt_secret(user_id: str) -> str:
    """获取用户的JWT签名密钥，不存在则创建"""
    data = _load_user_auth_data(user_id)
    if not data:
        # 创建新的认证数据
        secret = secrets.token_hex(32)
        data = {
            "user_id": user_id,
            "password_hash": "",
            "password_salt": "",
            "jwt_secret": secret
        }
        _save_user_auth_data(data)
        return secret
    
    secret = data.get("jwt_secret", "")
    if not secret:
        secret = secrets.token_hex(32)
        data["jwt_secret"] = secret
        _save_user_auth_data(data)
    
    return secret


def create_user_token(user_id: str, username: str, is_admin: bool = False) -> str:
    """创建用户JWT令牌"""
    import base64
    
    secret = _get_user_jwt_secret(user_id)
    payload = json.dumps({
        "sub": user_id,           # 用户ID
        "username": username,     # 用户名（显示用）
        "is_admin": is_admin,     # 管理员标志
        "iat": int(time.time()),  # 签发时间
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS  # 过期时间
    })
    
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(
        secret.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()
    
    return f"{payload_b64}.{sig}"


def verify_user_token(token: str) -> Optional[Dict]:
    """验证用户令牌，返回用户信息字典"""
    import base64
    
    try:
        parts = token.split(".", 1)
        if len(parts) != 2:
            return None
        
        payload_b64, sig = parts
        
        # 解码payload获取user_id
        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        # 检查过期时间
        if payload.get("exp", 0) < time.time():
            return None
        
        # 获取用户密钥验证签名
        secret = _get_user_jwt_secret(user_id)
        expected_sig = hmac.new(
            secret.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()
        
        if not hmac.compare_digest(sig, expected_sig):
            return None
        
        # 验证用户状态
        profile = _load_user_profile(user_id)
        if not profile or not profile.enabled:
            return None
        
        return {
            "user_id": user_id,
            "username": profile.username,
            "is_admin": profile.is_admin
        }
        
    except (json.JSONDecodeError, KeyError, ValueError, TypeError,
            base64.binascii.Error) as exc:
        logger.debug(f"Token verification failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# 用户管理
# ---------------------------------------------------------------------------


def is_auth_enabled() -> bool:
    """检查认证是否启用"""
    env_flag = EnvVarLoader.get_str("QWENPAW_AUTH_ENABLED", "").strip().lower()
    # 默认启用认证，除非明确设置为false
    if env_flag == "":
        return True
    return env_flag in ("true", "1", "yes")


def has_registered_users() -> bool:
    """检查是否有已注册用户"""
    index = _load_users_index()
    return len(index) > 0


def register_user(username: str, password: str, email: Optional[str] = None,
                  is_admin: bool = False) -> Optional[Dict]:
    """注册新用户"""
    if not is_auth_enabled():
        logger.warning("Authentication is not enabled")
        return None
    
    # 检查用户名是否已存在
    existing_user_id = _get_user_id_by_username(username)
    if existing_user_id:
        logger.warning(f"Username already exists: {username}")
        return None
    
    # 生成用户ID
    user_id = f"u_{secrets.token_hex(8)}"  # u_ + 16位十六进制
    
    # 创建密码哈希
    password_hash, password_salt = _hash_password(password)
    
    # 生成JWT密钥
    jwt_secret = secrets.token_hex(32)
    
    # 创建用户信息
    profile = UserProfile(
        user_id=user_id,
        username=username,
        email=email,
        is_admin=is_admin
    )
    
    # 创建认证数据
    auth_data = {
        "user_id": user_id,
        "password_hash": password_hash,
        "password_salt": password_salt,
        "jwt_secret": jwt_secret
    }
    
    # 保存数据
    _save_user_profile(profile)
    _save_user_auth_data(auth_data)
    _add_user_to_index(username, user_id)
    
    # 创建用户目录结构
    _get_user_workspace_root(user_id).mkdir(parents=True, exist_ok=True)
    
    logger.info(f"User registered: {username} ({user_id})")
    
    # 生成初始令牌
    token = create_user_token(user_id, username, is_admin)
    
    return {
        "user_id": user_id,
        "username": username,
        "token": token,
        "is_admin": is_admin
    }


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """用户认证，返回令牌和用户信息"""
    if not is_auth_enabled():
        return None
    
    # 查找用户
    user_id = _get_user_id_by_username(username)
    if not user_id:
        return None
    
    # 加载认证数据
    auth_data = _load_user_auth_data(user_id)
    if not auth_data:
        return None
    
    # 验证密码
    stored_hash = auth_data.get("password_hash", "")
    stored_salt = auth_data.get("password_salt", "")
    if not stored_hash or not stored_salt:
        return None
    
    if not verify_password(password, stored_hash, stored_salt):
        return None
    
    # 加载用户信息
    profile = _load_user_profile(user_id)
    if not profile or not profile.enabled:
        return None
    
    # 更新最后登录时间
    profile.last_login = datetime.utcnow().isoformat()
    _save_user_profile(profile)
    
    # 生成令牌
    token = create_user_token(user_id, username, profile.is_admin)
    
    return {
        "user_id": user_id,
        "username": username,
        "token": token,
        "is_admin": profile.is_admin
    }


def update_user_password(user_id: str, current_password: str, 
                         new_password: str) -> bool:
    """更新用户密码"""
    auth_data = _load_user_auth_data(user_id)
    if not auth_data:
        return False
    
    # 验证当前密码
    stored_hash = auth_data.get("password_hash", "")
    stored_salt = auth_data.get("password_salt", "")
    if not verify_password(current_password, stored_hash, stored_salt):
        return False
    
    # 生成新密码哈希
    new_hash, new_salt = _hash_password(new_password)
    
    # 更新数据
    auth_data["password_hash"] = new_hash
    auth_data["password_salt"] = new_salt
    # 轮换JWT密钥使旧令牌失效
    auth_data["jwt_secret"] = secrets.token_hex(32)
    
    _save_user_auth_data(auth_data)
    logger.info(f"Password updated for user: {user_id}")
    
    return True


def delete_user(user_id: str) -> bool:
    """删除用户（需要管理员权限调用）"""
    # 查找用户名
    profile = _load_user_profile(user_id)
    if not profile:
        return False
    
    # 从索引中移除
    _remove_user_from_index(profile.username)
    
    # 删除用户目录
    user_dir = _get_user_dir(user_id)
    try:
        import shutil
        shutil.rmtree(user_dir, ignore_errors=True)
    except Exception as e:
        logger.error(f"Failed to delete user directory {user_dir}: {e}")
    
    logger.info(f"User deleted: {user_id}")
    return True


# ---------------------------------------------------------------------------
# 认证中间件
# ---------------------------------------------------------------------------


class MultiUserAuthMiddleware(BaseHTTPMiddleware):
    """多用户认证中间件"""
    
    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        """检查Bearer令牌，设置用户上下文"""
        logger = logging.getLogger(__name__)
        
        should_skip = self._should_skip_auth(request)
        logger.info(f"MultiUserAuthMiddleware: path={request.url.path}, should_skip={should_skip}, method={request.method}")
        
        if should_skip:
            return await call_next(request)
        
        token = self._extract_token(request)
        logger.info(f"MultiUserAuthMiddleware: token extracted: {'Yes' if token else 'No'}")
        if not token:
            logger.warning(f"MultiUserAuthMiddleware: No token found for path {request.url.path}")
            return Response(
                content=json.dumps({"detail": "Not authenticated"}),
                status_code=401,
                media_type="application/json",
            )
        
        user_info = verify_user_token(token)
        if user_info is None:
            logger.warning(f"MultiUserAuthMiddleware: Invalid or expired token for path {request.url.path}")
            return Response(
                content=json.dumps({"detail": "Invalid or expired token"}),
                status_code=401,
                media_type="application/json",
            )
        
        # 设置请求上下文
        request.state.user_id = user_info["user_id"]
        request.state.username = user_info["username"]
        request.state.is_admin = user_info.get("is_admin", False)
        
        logger.info(f"MultiUserAuthMiddleware: Authenticated user {user_info['user_id']} ({user_info['username']}) for path {request.url.path}")
        return await call_next(request)
    
    @staticmethod
    def _should_skip_auth(request: Request) -> bool:
        """检查是否需要跳过认证"""
        logger = logging.getLogger(__name__)
        
        auth_enabled = is_auth_enabled()
        has_users = has_registered_users()
        logger.info(f"_should_skip_auth: auth_enabled={auth_enabled}, has_users={has_users}")
        
        if not auth_enabled or not has_users:
            logger.info(f"_should_skip_auth: skipping auth (auth_enabled={auth_enabled}, has_users={has_users})")
            return True
        
        path = request.url.path
        
        if request.method == "OPTIONS":
            logger.info(f"_should_skip_auth: skipping auth for OPTIONS method")
            return True
        
        if path in _PUBLIC_PATHS or any(
            path.startswith(p) for p in _PUBLIC_PREFIXES
        ):
            logger.info(f"_should_skip_auth: path {path} is in public paths")
            return True
        
        # 仅保护 /api/ 路径
        if not path.startswith("/api/"):
            logger.info(f"_should_skip_auth: path {path} is not under /api/")
            return True
        
        logger.info(f"_should_skip_auth: path {path} requires authentication")
        return False
    
    @staticmethod
    def _extract_token(request: Request) -> Optional[str]:
        """从请求中提取令牌"""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        if "upgrade" in request.headers.get("connection", "").lower():
            return request.query_params.get("token")
        
        token = request.query_params.get("token")
        if token:
            return token
        return None


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def get_current_user_id(request: Request) -> Optional[str]:
    """获取当前用户ID"""
    return getattr(request.state, "user_id", None)


def require_current_user(request: Request) -> str:
    """获取当前用户ID，如果不存在则抛出异常"""
    user_id = get_current_user_id(request)
    if not user_id:
        raise ValueError("No authenticated user")
    return user_id


def get_user_workspace_root(user_id: str) -> Path:
    """获取用户工作区根目录"""
    return _get_user_workspace_root(user_id)


def migrate_single_user_to_multi_user() -> bool:
    """迁移单用户数据到多用户系统"""
    # 检查是否存在旧版 auth.json
    old_auth_file = SECRET_DIR / "auth.json"
    if not old_auth_file.exists():
        logger.info("No legacy single-user data found")
        return True
    
    try:
        with open(old_auth_file, "r", encoding="utf-8") as f:
            old_data = json.load(f)
        
        # 解密旧数据
        old_data = decrypt_dict_fields(old_data, AUTH_SECRET_FIELDS)
        
        user = old_data.get("user")
        if not user:
            logger.warning("Legacy auth.json has no user data")
            return False
        
        old_username = user.get("username")
        if not old_username:
            logger.warning("Legacy user has no username")
            return False
        
        # 检查是否已存在该用户
        existing_id = _get_user_id_by_username(old_username)
        if existing_id:
            logger.info(f"User {old_username} already exists in multi-user system")
            return True
        
        # 创建管理员用户
        result = register_user(
            username=old_username,
            password="",  # 密码无法迁移，需要重置
            is_admin=True
        )
        
        if not result:
            logger.error("Failed to migrate user")
            return False
        
        user_id = result["user_id"]
        
        # 迁移认证数据（如果可能）
        auth_data = _load_user_auth_data(user_id)
        if auth_data and user.get("password_hash") and user.get("password_salt"):
            auth_data["password_hash"] = user["password_hash"]
            auth_data["password_salt"] = user["password_salt"]
            _save_user_auth_data(auth_data)
        
        logger.info(f"Migrated single user {old_username} to multi-user system")
        logger.warning("Password not migrated, user needs to reset password")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to migrate single user data: {e}")
        return False


def auto_register_admin_from_env() -> None:
    """从环境变量自动注册管理员用户
    
    在应用启动时调用。如果 QWENPAW_AUTH_ENABLED 为真，
    且 QWENPAW_AUTH_USERNAME 和 QWENPAW_AUTH_PASSWORD 环境变量已设置，
    则自动创建管理员账户。
    """
    if not is_auth_enabled():
        return
    
    username = EnvVarLoader.get_str("QWENPAW_AUTH_USERNAME", "").strip()
    password = EnvVarLoader.get_str("QWENPAW_AUTH_PASSWORD", "").strip()
    if not username or not password:
        return
    
    # 检查用户是否已存在
    existing_id = _get_user_id_by_username(username)
    if existing_id:
        logger.info(f"User {username} already exists, skipping auto-registration")
        return
    
    # 注册管理员用户
    result = register_user(
        username=username,
        password=password,
        is_admin=True
    )
    
    if result:
        logger.info(
            "Auto-registered admin user '%s' from environment variables",
            username,
        )
    else:
        logger.warning(
            "Failed to auto-register admin user '%s' from environment variables",
            username,
        )