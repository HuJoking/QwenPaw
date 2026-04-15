# -*- coding: utf-8 -*-
"""多用户认证 API 端点"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ...constant import EnvVarLoader
from ...config.config import load_agent_config
from ...config.utils import load_config
from ..user_auth import (
    authenticate_user,
    has_registered_users,
    is_auth_enabled,
    register_user,
    update_user_password,
    verify_user_token,
    get_current_user_id,
    delete_user,
    _load_user_profile,
    _load_users_index,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    user_id: str
    username: str
    token: str
    is_admin: bool


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
    is_admin: bool = False


class AuthStatusResponse(BaseModel):
    enabled: bool
    has_users: bool
    user_count: int


class UserProfileResponse(BaseModel):
    user_id: str
    username: str
    email: str | None
    created_at: str
    last_login: str | None
    enabled: bool
    is_admin: bool


class UpdatePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
async def login(req: LoginRequest):
    """用户登录"""
    if not is_auth_enabled():
        return LoginResponse(
            user_id="",
            username="",
            token="",
            is_admin=False
        )
    
    result = authenticate_user(req.username, req.password)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return LoginResponse(**result)


@router.post("/register")
async def register(req: RegisterRequest):
    """注册新用户（需要认证启用）"""
    env_flag = EnvVarLoader.get_str("QWENPAW_AUTH_ENABLED", "").strip().lower()
    if env_flag not in ("true", "1", "yes"):
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    if not req.username.strip() or not req.password.strip():
        raise HTTPException(
            status_code=400,
            detail="Username and password are required",
        )
    
    result = register_user(
        username=req.username.strip(),
        password=req.password,
        email=req.email,
        is_admin=req.is_admin
    )
    
    if result is None:
        raise HTTPException(
            status_code=409,
            detail="Registration failed (username may already exist)",
        )
    
    return LoginResponse(**result)


@router.get("/status")
async def auth_status():
    """检查认证状态"""
    index = _load_users_index()
    return AuthStatusResponse(
        enabled=is_auth_enabled(),
        has_users=has_registered_users(),
        user_count=len(index)
    )


@router.get("/verify")
async def verify(request: Request):
    """验证当前令牌"""
    if not is_auth_enabled():
        return {"valid": True, "user_id": "", "username": ""}
    
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )
    
    return {
        "valid": True,
        "user_id": user_info["user_id"],
        "username": user_info["username"],
        "is_admin": user_info.get("is_admin", False)
    }


@router.post("/update-password")
async def update_password(req: UpdatePasswordRequest, request: Request):
    """更新当前用户密码"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    if not has_registered_users():
        raise HTTPException(
            status_code=403,
            detail="No users registered",
        )
    
    # 验证当前令牌
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = user_info["user_id"]
    
    if not req.new_password.strip():
        raise HTTPException(
            status_code=400,
            detail="New password cannot be empty",
        )
    
    success = update_user_password(
        user_id=user_id,
        current_password=req.current_password,
        new_password=req.new_password
    )
    
    if not success:
        raise HTTPException(
            status_code=401,
            detail="Current password is incorrect",
        )
    
    # 生成新令牌（JWT密钥已轮换）
    profile = _load_user_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")
    
    from ..user_auth import create_user_token
    new_token = create_user_token(user_id, profile.username, profile.is_admin)
    
    return LoginResponse(
        user_id=user_id,
        username=profile.username,
        token=new_token,
        is_admin=profile.is_admin
    )


@router.get("/profile")
async def get_profile(request: Request):
    """获取当前用户信息"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    profile = _load_user_profile(user_info["user_id"])
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserProfileResponse(
        user_id=profile.user_id,
        username=profile.username,
        email=profile.email,
        created_at=profile.created_at,
        last_login=profile.last_login,
        enabled=profile.enabled,
        is_admin=profile.is_admin
    )


# 管理员接口
@router.get("/users")
async def list_users(request: Request):
    """列出所有用户（管理员专用）"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    # 验证管理员权限
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not user_info.get("is_admin", False):
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required",
        )
    
    # 加载所有用户
    index = _load_users_index()
    users = []
    
    for username, user_id in index.items():
        profile = _load_user_profile(user_id)
        if profile:
            users.append(UserProfileResponse(
                user_id=profile.user_id,
                username=profile.username,
                email=profile.email,
                created_at=profile.created_at,
                last_login=profile.last_login,
                enabled=profile.enabled,
                is_admin=profile.is_admin
            ))
    
    return users


@router.delete("/users/{user_id}")
async def delete_user_endpoint(user_id: str, request: Request):
    """删除用户（管理员专用）"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    # 验证管理员权限
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not user_info.get("is_admin", False):
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required",
        )
    
    # 不能删除自己
    if user_id == user_info["user_id"]:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own account",
        )
    
    success = delete_user(user_id)
    if not success:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )
    
    return {"success": True, "message": f"User {user_id} deleted"}


# ---------------------------------------------------------------------------
# Agent所有权管理接口
# ---------------------------------------------------------------------------

class AgentOwnershipRequest(BaseModel):
    agent_id: str
    user_id: str


class AgentOwnershipResponse(BaseModel):
    agent_id: str
    user_id: str
    username: str


@router.post("/agent-ownership")
async def assign_agent_ownership(req: AgentOwnershipRequest, request: Request):
    """分配Agent所有权（管理员专用）"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    # 验证管理员权限
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not user_info.get("is_admin", False):
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required",
        )
    
    # 检查用户是否存在
    target_profile = _load_user_profile(req.user_id)
    if not target_profile:
        raise HTTPException(
            status_code=404,
            detail=f"Target user not found: {req.user_id}"
        )
    
    # 分配Agent所有权
    try:
        from ..user_context import register_agent_owner
        register_agent_owner(req.agent_id, req.user_id)
        
        return AgentOwnershipResponse(
            agent_id=req.agent_id,
            user_id=req.user_id,
            username=target_profile.username
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to assign agent ownership: {str(e)}"
        )


@router.get("/agent-ownership/{agent_id}")
async def get_agent_ownership(agent_id: str, request: Request):
    """获取Agent所有权信息"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    # 验证用户权限
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # 非管理员只能查询自己拥有的Agent
    from ..user_context import get_agent_owner
    owner_id = get_agent_owner(agent_id)
    
    if not user_info.get("is_admin", False) and owner_id != user_info["user_id"]:
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )
    
    if owner_id:
        owner_profile = _load_user_profile(owner_id)
        if owner_profile:
            return AgentOwnershipResponse(
                agent_id=agent_id,
                user_id=owner_id,
                username=owner_profile.username
            )
    
    return {"agent_id": agent_id, "owner": None}


@router.get("/user-agents/{user_id}")
async def list_user_agents(user_id: str, request: Request):
    """列出用户拥有的所有Agent（管理员或用户自己）"""
    if not is_auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Authentication is not enabled",
        )
    
    # 验证用户权限
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    user_info = verify_user_token(token)
    if user_info is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # 只能查看自己的Agent，除非是管理员
    if not user_info.get("is_admin", False) and user_id != user_info["user_id"]:
        raise HTTPException(
            status_code=403,
            detail="Can only view your own agents"
        )
    
    from ..user_context import list_user_agents
    agent_ids = list_user_agents(user_id)
    
    # 获取Agent详情
    config = load_config()
    agents = []
    
    for agent_id in agent_ids:
        if agent_id in config.agents.profiles:
            agent_ref = config.agents.profiles[agent_id]
            try:
                agent_config = load_agent_config(agent_id)
                agents.append({
                    "id": agent_id,
                    "name": agent_config.name,
                    "workspace_dir": agent_ref.workspace_dir,
                    "enabled": getattr(agent_ref, "enabled", True)
                })
            except Exception:
                agents.append({
                    "id": agent_id,
                    "name": agent_id.title(),
                    "workspace_dir": agent_ref.workspace_dir,
                    "enabled": getattr(agent_ref, "enabled", True)
                })
    
    return {"user_id": user_id, "agents": agents}