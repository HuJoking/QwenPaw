# -*- coding: utf-8 -*-
"""Agent context utilities for multi-agent support.

Provides utilities to get the correct agent instance for each request.
扩展支持多用户权限验证。
"""
from contextvars import ContextVar
from typing import Optional, TYPE_CHECKING
from fastapi import Request
from .multi_agent_manager import MultiAgentManager
from ..config.utils import load_config

if TYPE_CHECKING:
    from .workspace import Workspace

# Context variable to store current agent ID across async calls
_current_agent_id: ContextVar[Optional[str]] = ContextVar(
    "current_agent_id",
    default=None,
)

# Context variable to store current session id across async calls
_current_session_id: ContextVar[Optional[str]] = ContextVar(
    "current_session_id",
    default=None,
)


async def get_agent_for_request(
    request: Request,
    agent_id: Optional[str] = None,
) -> "Workspace":
    """Get agent workspace for current request with user permission check.

    Priority:
    1. agent_id parameter (explicit override)
    2. request.state.agent_id (from agent-scoped router)
    3. X-Agent-Id header (from frontend)
    4. Active agent from config

    Args:
        request: FastAPI request object
        agent_id: Agent ID override (highest priority)

    Returns:
        Workspace for the specified or active agent

    Raises:
        HTTPException: If agent not found or access denied
    """
    from fastapi import HTTPException

    # Determine which agent to use
    target_agent_id = agent_id

    # Check request.state.agent_id (set by agent-scoped router)
    if not target_agent_id and hasattr(request.state, "agent_id"):
        target_agent_id = request.state.agent_id

    # Check X-Agent-Id header
    if not target_agent_id:
        target_agent_id = request.headers.get("X-Agent-Id")

    # Load config once for fallback and validation
    config = None
    if not target_agent_id:
        # Fallback to active agent from config
        config = load_config()
        target_agent_id = config.agents.active_agent or "default"

    # Check if agent exists and is enabled
    if config is None:
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

    # 用户权限验证（如果启用了多用户认证）
    user_id = getattr(request.state, "user_id", None)
    if user_id:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"get_agent_for_request: user_id={user_id}, agent_id={target_agent_id}")
        # 导入用户上下文进行权限验证
        try:
            from .user_context import validate_agent_access
            if validate_agent_access(user_id, target_agent_id):
                logger.info(f"get_agent_for_request: user {user_id} has access to agent {target_agent_id}")
            else:
                logger.warning(f"get_agent_for_request: user {user_id} NO access to agent {target_agent_id}")
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied to agent '{target_agent_id}'",
                )
        except HTTPException:
            raise
        except Exception as e:
            # user_context模块不存在或有其他错误，记录错误但跳过权限验证（向后兼容）
            logger.warning(f"权限验证失败，跳过权限检查: {e}")
            # 在调试模式下，可以记录更多信息
            # import traceback
            # logger.debug(f"权限验证失败详情: {traceback.format_exc()}")

    # Get MultiAgentManager
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
        
        # 设置当前Agent ID到上下文
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


def get_active_agent_id() -> str:
    """Get current active agent ID from config.

    Returns:
        Active agent ID, defaults to "default"
    """
    try:
        config = load_config()
        return config.agents.active_agent or "default"
    except Exception:
        return "default"


def set_current_agent_id(agent_id: str) -> None:
    """Set current agent ID in context.

    Args:
        agent_id: Agent ID to set
    """
    _current_agent_id.set(agent_id)


def get_current_agent_id() -> str:
    """Get current agent ID from context or config fallback.

    Returns:
        Current agent ID, defaults to active agent or "default"
    """
    agent_id = _current_agent_id.get()
    if agent_id:
        return agent_id
    return get_active_agent_id()


def set_current_session_id(session_id: str) -> None:
    _current_session_id.set(session_id)


def get_current_session_id() -> Optional[str]:
    return _current_session_id.get()
