from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.auth import TokenData, require_role
from backend.database import get_db
from backend.analysis.playbook_store import PlaybookStore
from backend.utils.audit import write_audit_log

router = APIRouter(prefix="/api/admin", tags=["Playbooks"])
store = PlaybookStore()

@router.get("/playbooks")
def list_playbooks(current_user: TokenData = Depends(require_role("admin"))):
    return {"profile": store.active_profile(), "incident_types": store.list_incident_types()}

@router.post("/playbooks/reload")
def reload_playbooks(
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    data = store.reload()
    write_audit_log(
        db,
        "playbooks_reloaded",
        {"count": len(data), "profile": store.active_profile()},
        user_id=current_user.user_id
    )
    return {"reloaded": True, "profile": store.active_profile(), "count": len(data), "incident_types": sorted(list(data.keys()))}