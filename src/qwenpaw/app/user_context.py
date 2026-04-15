# -*- coding: utf-8 -*-
"""用户上下文管理：用户权限验证与Agent访问控制。

扩展原有的agent上下文，加入多用户支持：
1. 验证用户对Agent的访问权限
2. 用户工作区路径管理
3. Agent所有权验证
"""
from __future__ import annotations

import logging
import json
from pathlib import Path
from typing import Optional, Dict, List, Set
from contextvars import ContextVar

from fastapi import Request, HTTPException

from .user_auth import get_current_user_id, require_current_user
from ..config.utils import load_config, save_config
from ..constant import WORKING_DIR

logger = logging.getLogger(__name__)

# 用户工作区根目录
USERS_DIR = WORKING_DIR / "local" / "users"

# Agent所有权映射文件
AGENT_OWNERS_FILE = WORKING_DIR / "local" / "system" / "agent_owners.json"

# 上下文变量
_current_user_id: ContextVar[Optional[str]] = ContextVar("current_user_id", default=None)
_current_agent_id: ContextVar[Optional[str]] = ContextVar("current_agent_id", default=None)


# ---------------------------------------------------------------------------
# Agent所有权管理
# ---------------------------------------------------------------------------

def _load_agent_owners() -> Dict[str, str]:
    """加载Agent所有者映射"""
    if AGENT_OWNERS_FILE.exists():
        try:
            with open(AGENT_OWNERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load agent owners: {e}")
    return {}


def _save_agent_owners(owners: Dict[str, str]) -> None:
    """保存Agent所有者映射"""
    AGENT_OWNERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(AGENT_OWNERS_FILE, "w", encoding="utf-8") as f:
            json.dump(owners, f, indent=2)
    except IOError as e:
        logger.error(f"Failed to save agent owners: {e}")
        raise


def register_agent_owner(agent_id: str, user_id: str) -> None:
    """注册Agent所有者"""
    owners = _load_agent_owners()
    owners[agent_id] = user_id
    _save_agent_owners(owners)
    logger.info(f"Registered agent {agent_id} owner: {user_id}")


def get_agent_owner(agent_id: str) -> Optional[str]:
    """获取Agent所有者"""
    owners = _load_agent_owners()
    return owners.get(agent_id)


def transfer_agent_ownership(agent_id: str, new_user_id: str, 
                           requester_user_id: str) -> bool:
    """转移Agent所有权（需要当前所有者或管理员权限）"""
    owners = _load_agent_owners()
    current_owner = owners.get(agent_id)
    
    if not current_owner:
        # Agent未注册，直接分配
        owners[agent_id] = new_user_id
        _save_agent_owners(owners)
        return True
    
    # 验证请求者权限
    if current_owner != requester_user_id:
        # 检查是否为管理员
        from .user_auth import _load_user_profile
        profile = _load_user_profile(requester_user_id)
        if not profile or not profile.is_admin:
            return False
    
    owners[agent_id] = new_user_id
    _save_agent_owners(owners)
    logger.info(f"Transferred agent {agent_id} from {current_owner} to {new_user_id}")
    return True


def delete_agent_ownership(agent_id: str) -> bool:
    """删除Agent所有权记录"""
    owners = _load_agent_owners()
    if agent_id in owners:
        del owners[agent_id]
        _save_agent_owners(owners)
        logger.info(f"Deleted agent ownership record: {agent_id}")
        return True
    return False


def list_user_agents(user_id: str) -> List[str]:
    """列出用户拥有的所有Agent"""
    owners = _load_agent_owners()
    return [agent_id for agent_id, owner_id in owners.items() 
            if owner_id == user_id]


# ---------------------------------------------------------------------------
# 用户工作区路径管理
# ---------------------------------------------------------------------------

def get_user_workspace_root(user_id: str) -> Path:
    """获取用户工作区根目录"""
    return USERS_DIR / user_id / "workspaces"


def get_user_agent_workspace_dir(user_id: str, agent_id: str) -> Path:
    """获取用户Agent工作区目录"""
    return get_user_workspace_root(user_id) / agent_id


def validate_agent_access(user_id: str, agent_id: str) -> bool:
    """验证用户是否有权访问Agent（严格模式：要求工作区在用户目录下）
    
    规则：
    1. 管理员可以访问所有Agent
    2. 非管理员用户必须同时满足：
       a) 是Agent的所有者（通过agent_owners.json）
       b) Agent工作区在用户专属目录下
    """
    logger.info(f"validate_agent_access: user={user_id}, agent={agent_id}")
    
    # 管理员可以访问所有Agent
    from .user_auth import _load_user_profile
    profile = _load_user_profile(user_id)
    if profile and profile.is_admin:
        logger.info(f"validate_agent_access: user {user_id} is admin, allowing access to {agent_id}")
        return True
    
    try:
        # 尝试加载配置，如果失败则直接读取配置文件
        try:
            config = load_config()
            if agent_id not in config.agents.profiles:
                return False
            
            workspace_dir_str = config.agents.profiles[agent_id].workspace_dir
        except Exception as config_error:
            # 如果load_config失败，尝试直接读取配置文件
            logger.warning(f"load_config失败，尝试直接读取配置文件: {config_error}")
            try:
                # 直接读取config.json文件
                from ..constant import WORKING_DIR
                config_path = WORKING_DIR / "local" / "config.json"
                if not config_path.exists():
                    return False
                
                import json
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                profiles = config_data.get("agents", {}).get("profiles", {})
                if agent_id not in profiles:
                    return False
                
                workspace_dir_str = profiles[agent_id].get("workspace_dir", "")
                if not workspace_dir_str:
                    return False
            except Exception as file_error:
                logger.error(f"读取配置文件失败: {file_error}")
                return False
        
        # 检查Agent所有权
        owner = get_agent_owner(agent_id)
        logger.info(f"validate_agent_access: agent {agent_id} owner={owner}, user={user_id}")
        if not owner or owner != user_id:
            logger.info(f"validate_agent_access: user {user_id} is not owner of agent {agent_id} (owner={owner})")
            return False
        
        # 检查工作区是否在用户目录下（物理隔离要求）
        workspace_dir = Path(workspace_dir_str).expanduser()
        user_workspace_root = get_user_workspace_root(user_id)
        
        is_in_user_dir = str(workspace_dir).startswith(str(user_workspace_root))
        
        logger.info(f"validate_agent_access: workspace_dir={workspace_dir}")
        logger.info(f"validate_agent_access: user_workspace_root={user_workspace_root}")
        logger.info(f"validate_agent_access: is_in_user_dir={is_in_user_dir}")
        
        if not is_in_user_dir:
            logger.warning(
                f"Agent {agent_id} owned by user {user_id} but workspace is not in user directory. "
                f"Workspace: {workspace_dir}, User dir: {user_workspace_root}"
            )
            # 在严格模式下，即使所有权匹配，工作区不在用户目录也不允许访问
            # 这强制要求物理隔离
            return False
        
        logger.info(f"validate_agent_access: user {user_id} has access to agent {agent_id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to validate agent access: {e}")
        return False


# ---------------------------------------------------------------------------
# 上下文管理
# ---------------------------------------------------------------------------

def set_current_user_id(user_id: str) -> None:
    """设置当前用户ID到上下文"""
    _current_user_id.set(user_id)


def get_current_user_id_from_context() -> Optional[str]:
    """从上下文中获取当前用户ID"""
    return _current_user_id.get()


def require_current_user_from_context() -> str:
    """获取当前用户ID，不存在则抛出异常"""
    user_id = get_current_user_id_from_context()
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user_id


def set_current_agent_id(agent_id: str) -> None:
    """设置当前Agent ID到上下文"""
    _current_agent_id.set(agent_id)


def get_current_agent_id_from_context() -> Optional[str]:
    """从上下文中获取当前Agent ID"""
    return _current_agent_id.get()


# ---------------------------------------------------------------------------
# 请求处理辅助函数
# ---------------------------------------------------------------------------

async def get_agent_for_user_request(
    request: Request,
    agent_id: Optional[str] = None,
) -> "Workspace":
    """获取用户的Agent工作区（带权限验证）"""
    from .multi_agent_manager import MultiAgentManager
    
    # 获取当前用户
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # 确定目标Agent
    target_agent_id = agent_id
    
    # 检查请求中的Agent ID
    if not target_agent_id and hasattr(request.state, "agent_id"):
        target_agent_id = request.state.agent_id
    
    if not target_agent_id:
        target_agent_id = request.headers.get("X-Agent-Id")
    
    # 加载配置获取默认Agent
    if not target_agent_id:
        config = load_config()
        target_agent_id = config.agents.active_agent or "default"
    
    # 验证用户权限
    if not validate_agent_access(user_id, target_agent_id):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to agent '{target_agent_id}'",
        )
    
    # 检查Agent是否存在且启用
    config = load_config()
    if target_agent_id not in config.agents.profiles:
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{target_agent_id}' not found",
        )
    
    agent_ref = config.agents.profiles[target_agent_id]
    if not getattr(agent_ref, "enabled", True):
        raise HTTPException(
            status_code=403,
            detail=f"Agent '{target_agent_id}' is disabled",
        )
    
    # 获取MultiAgentManager
    if not hasattr(request.app.state, "multi_agent_manager"):
        raise HTTPException(
            status_code=500,
            detail="MultiAgentManager not initialized",
        )
    
    manager: MultiAgentManager = request.app.state.multi_agent_manager
    
    try:
        workspace = await manager.get_agent(target_agent_id)
        if not workspace:
            raise HTTPException(
                status_code=404,
                detail=f"Agent '{target_agent_id}' not found",
            )
        
        # 设置上下文
        set_current_user_id(user_id)
        set_current_agent_id(target_agent_id)
        
        return workspace
        
    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e),
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get agent: {str(e)}",
        ) from e


def get_user_accessible_agents(user_id: str) -> List[Dict]:
    """获取用户可访问的所有Agent信息"""
    from .user_auth import _load_user_profile
    profile = _load_user_profile(user_id)
    is_admin = profile and profile.is_admin
    
    config = load_config()
    accessible_agents = []
    
    for agent_id, agent_ref in config.agents.profiles.items():
        # 管理员可以访问所有Agent
        if is_admin or validate_agent_access(user_id, agent_id):
            accessible_agents.append({
                "id": agent_id,
                "workspace_dir": agent_ref.workspace_dir,
                "enabled": getattr(agent_ref, "enabled", True),
                "owner": get_agent_owner(agent_id) or "system"
            })
    
    return accessible_agents


# ---------------------------------------------------------------------------
# 迁移工具
# ---------------------------------------------------------------------------

def migrate_existing_agents_to_users() -> Dict[str, int]:
    """将现有Agent迁移到用户系统
    
    为每个现有Agent分配所有者：
    1. 查找所有已配置的Agent
    2. 为每个Agent分配默认所有者（首个管理员或创建虚拟用户）
    3. 更新工作区路径到用户目录（可选）
    
    返回：统计信息字典
    """
    from .user_auth import _load_users_index, _load_user_profile
    
    stats = {
        "total_agents": 0,
        "migrated_agents": 0,
        "failed_agents": 0
    }
    
    try:
        config = load_config()
        stats["total_agents"] = len(config.agents.profiles)
        
        # 查找管理员用户
        admin_user_id = None
        index = _load_users_index()
        for username, user_id in index.items():
            profile = _load_user_profile(user_id)
            if profile and profile.is_admin:
                admin_user_id = user_id
                break
        
        if not admin_user_id and index:
            # 使用第一个用户作为默认所有者
            first_user_id = list(index.values())[0]
            admin_user_id = first_user_id
        
        if not admin_user_id:
            logger.warning("No users found for agent migration")
            return stats
        
        # 迁移每个Agent
        for agent_id, agent_ref in config.agents.profiles.items():
            try:
                # 注册Agent所有者
                register_agent_owner(agent_id, admin_user_id)
                stats["migrated_agents"] += 1
                logger.info(f"Migrated agent {agent_id} to user {admin_user_id}")
                
            except Exception as e:
                logger.error(f"Failed to migrate agent {agent_id}: {e}")
                stats["failed_agents"] += 1
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to migrate existing agents: {e}")
        return stats


def migrate_agent_workspaces_to_user_dirs() -> Dict[str, int]:
    """将Agent工作区迁移到用户专属目录
    
    将现有的共享工作区目录移动到用户目录下：
    1. 检查每个Agent的所有者
    2. 如果工作区仍在共享目录中，则迁移到用户目录
    3. 更新配置中的workspace_dir路径
    4. 更新agent.json文件中的路径（如果需要）
    
    返回：统计信息字典
    """
    import shutil
    from pathlib import Path
    
    stats = {
        "total_agents": 0,
        "migrated_workspaces": 0,
        "failed_migrations": 0,
        "skipped_workspaces": 0
    }
    
    try:
        config = load_config()
        stats["total_agents"] = len(config.agents.profiles)
        
        # 检查每个Agent
        for agent_id, agent_ref in config.agents.profiles.items():
            try:
                current_workspace_dir = Path(agent_ref.workspace_dir).expanduser()
                owner = get_agent_owner(agent_id)
                
                if not owner:
                    logger.warning(f"Agent {agent_id} has no owner, skipping workspace migration")
                    stats["skipped_workspaces"] += 1
                    continue
                
                # 检查工作区是否已在用户目录下
                user_workspace_root = get_user_workspace_root(owner)
                if str(current_workspace_dir).startswith(str(user_workspace_root)):
                    logger.debug(f"Agent {agent_id} workspace already in user directory, skipping")
                    stats["skipped_workspaces"] += 1
                    continue
                
                # 计算目标路径
                target_dir = get_user_agent_workspace_dir(owner, agent_id)
                
                if current_workspace_dir.exists():
                    # 确保目标目录不存在
                    if target_dir.exists():
                        logger.warning(f"Target directory already exists for agent {agent_id}: {target_dir}")
                        # 可以考虑删除或重命名现有目标目录
                        # 暂时跳过
                        stats["skipped_workspaces"] += 1
                        continue
                    
                    # 确保目标父目录存在
                    target_dir.parent.mkdir(parents=True, exist_ok=True)
                    
                    # 移动工作区目录
                    logger.info(f"Moving workspace for agent {agent_id}: {current_workspace_dir} -> {target_dir}")
                    shutil.move(str(current_workspace_dir), str(target_dir))
                    
                    # 更新配置中的workspace_dir
                    agent_ref.workspace_dir = str(target_dir)
                    stats["migrated_workspaces"] += 1
                    
                    # 尝试更新agent.json文件中的路径
                    agent_config_path = target_dir / "agent.json"
                    if agent_config_path.exists():
                        try:
                            with open(agent_config_path, "r", encoding="utf-8") as f:
                                agent_config_data = json.load(f)
                            
                            # 更新agent.json中的workspace_dir
                            agent_config_data["workspace_dir"] = str(target_dir)
                            
                            with open(agent_config_path, "w", encoding="utf-8") as f:
                                json.dump(agent_config_data, f, ensure_ascii=False, indent=2)
                            
                            logger.debug(f"Updated agent.json for {agent_id}")
                        except Exception as e:
                            logger.error(f"Failed to update agent.json for {agent_id}: {e}")
                    else:
                        logger.warning(f"No agent.json found for {agent_id} at {agent_config_path}")
                    
                    logger.info(f"Successfully migrated workspace for agent {agent_id}")
                    
                else:
                    logger.warning(f"Source workspace directory does not exist for agent {agent_id}: {current_workspace_dir}")
                    stats["skipped_workspaces"] += 1
                    
            except Exception as e:
                logger.error(f"Failed to migrate workspace for agent {agent_id}: {e}")
                stats["failed_migrations"] += 1
        
        # 保存更新后的配置
        if stats["migrated_workspaces"] > 0:
            save_config(config)
            logger.info(f"Saved updated configuration with {stats['migrated_workspaces']} migrated workspaces")
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to migrate agent workspaces: {e}")
        return stats