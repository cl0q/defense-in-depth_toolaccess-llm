"""
Restricted tool interface (DT).
The model can only choose from approved templates and provide parameters.
"""

from typing import Any, Dict, List
from fastapi import HTTPException

from .db import execute_transaction


_TEMPLATE_CATALOG: Dict[str, Dict[str, Any]] = {
    "get_my_orders": {
        "roles": ["customer", "merchant", "admin"],
        "sql": (
            "SELECT o.id, o.customer_id, o.merchant_id, o.tenant_id, o.total, o.status, o.note "
            "FROM orders o "
            "WHERE (%s::text IS NULL OR o.status = %s) "
            "ORDER BY o.id LIMIT %s"
        ),
        "params": ["status", "status", "limit"],
        "defaults": {"status": None, "limit": 20},
    },
    "get_order_details": {
        "roles": ["customer", "merchant", "admin"],
        "sql": (
            "SELECT o.id, o.customer_id, o.merchant_id, o.tenant_id, o.total, o.status, o.note "
            "FROM orders o WHERE o.id = %s"
        ),
        "params": ["order_id"],
        "defaults": {},
    },
    "update_order_status": {
        "roles": ["merchant", "admin"],
        "sql": "UPDATE orders SET status = %s WHERE id = %s RETURNING id, status",
        "params": ["new_status", "order_id"],
        "defaults": {},
    },
    "set_product_price": {
        "roles": ["merchant", "admin"],
        "sql": "UPDATE products SET price = %s WHERE id = %s RETURNING id, price",
        "params": ["price", "product_id"],
        "defaults": {},
    },
    "get_product_info": {
        "roles": ["customer", "merchant", "admin"],
        "sql": (
            "SELECT p.id, p.merchant_id, p.tenant_id, p.name, p.price, p.internal_cost "
            "FROM products p WHERE p.id = %s"
        ),
        "params": ["product_id"],
        "defaults": {},
    },
    "get_all_users": {
        "roles": ["admin"],
        "sql": (
            "SELECT id, role, tenant_id, merchant_id, username "
            "FROM platform_users ORDER BY id LIMIT %s"
        ),
        "params": ["limit"],
        "defaults": {"limit": 25},
    },
    "update_user_role": {
        "roles": ["admin"],
        "sql": "UPDATE platform_users SET role = %s WHERE id = %s RETURNING id, role",
        "params": ["new_role", "user_id"],
        "defaults": {},
    },
}


def get_allowed_templates_for_role(role: str) -> List[str]:
    return sorted(
        [name for name, cfg in _TEMPLATE_CATALOG.items() if role in cfg["roles"]]
    )


def execute_template(
    template_name: str,
    params: Dict[str, Any],
    identity: Dict[str, Any],
    trace_id: str,
) -> List[Dict[str, Any]]:
    role = identity.get("role", "customer")
    if template_name not in _TEMPLATE_CATALOG:
        raise HTTPException(status_code=400, detail=f"Unknown template: {template_name}")

    template = _TEMPLATE_CATALOG[template_name]
    if role not in template["roles"]:
        raise HTTPException(
            status_code=403,
            detail=f"Template {template_name} not permitted for role {role}",
        )

    resolved_params: List[Any] = []
    defaults = template.get("defaults", {})
    for key in template["params"]:
        if key in params:
            resolved_params.append(params[key])
            continue
        if key in defaults:
            resolved_params.append(defaults[key])
            continue
        raise HTTPException(
            status_code=400,
            detail=f"Missing template parameter: {key}",
        )

    return execute_transaction(
        [template["sql"]],
        resolved_params,
        identity,
        trace_id=trace_id,
    )
