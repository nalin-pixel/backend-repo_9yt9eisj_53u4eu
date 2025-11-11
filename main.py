import os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4

# Database helpers
from database import db, create_document, get_documents

app = FastAPI(title="InTrack API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# Auth & RBAC
# ----------------------

class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=6)
    role: str = Field(pattern=r"^(Admin|Manager|Engineer|Accountant)$")

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str

ALLOWED_ROLES = {"Admin", "Manager", "Engineer", "Accountant"}


def _collection(name: str):
    return db[name]


def _now():
    return datetime.now(timezone.utc)


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    session = _collection("session").find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = _collection("user").find_one({"_id": session["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "_id": str(user["_id"]),
        "name": user.get("name"),
        "email": user.get("email"),
        "role": user.get("role"),
    }


def require_roles(*roles: str):
    def checker(user = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker


@app.get("/")
def read_root():
    return {"message": "InTrack Backend running", "version": "0.1.0"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"
    return response


# ----------------------
# Auth Endpoints (Simple session tokens stored in DB)
# ----------------------

@app.post("/auth/register", response_model=UserOut)
def register(body: RegisterBody):
    if body.role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = _collection("user").find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    # NOTE: For demo purposes, password is stored as plain text. In production, hash it.
    data = {
        "name": body.name,
        "email": body.email,
        "password": body.password,
        "role": body.role,
        "created_at": _now(),
        "updated_at": _now(),
        "status": "active",
    }
    inserted_id = _collection("user").insert_one(data).inserted_id
    return {"id": str(inserted_id), "name": body.name, "email": body.email, "role": body.role}


@app.post("/auth/login")
def login(body: LoginBody):
    user = _collection("user").find_one({"email": body.email})
    if not user or user.get("password") != body.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = str(uuid4())
    _collection("session").insert_one({
        "token": token,
        "user_id": user["_id"],
        "created_at": _now(),
    })
    return {"token": token, "user": {"id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"), "role": user.get("role")}}


@app.get("/auth/me", response_model=UserOut)
async def me(user = Depends(get_current_user)):
    return {"id": user["_id"], "name": user["name"], "email": user["email"], "role": user["role"]}


@app.post("/auth/logout")
async def logout(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        return {"ok": True}
    token = authorization.split(" ", 1)[1]
    _collection("session").delete_one({"token": token})
    return {"ok": True}


# ----------------------
# Projects
# ----------------------
class ProjectIn(BaseModel):
    title: str
    client: str
    status: str = Field(default="active")
    manager_id: Optional[str] = None
    engineer_ids: List[str] = []

class ProjectOut(ProjectIn):
    id: str
    number: int


def _next_project_number() -> int:
    seq = _collection("counter").find_one_and_update(
        {"_id": "project_number"},
        {"$inc": {"value": 1}},
        upsert=True,
        return_document=True
    )
    return int(seq.get("value", 1))


@app.post("/projects", response_model=ProjectOut)
async def create_project(payload: ProjectIn, user=Depends(require_roles("Admin", "Manager"))):
    number = _next_project_number()
    doc = {
        "title": payload.title,
        "client": payload.client,
        "status": payload.status,
        "manager_id": payload.manager_id,
        "engineer_ids": payload.engineer_ids,
        "number": number,
        "created_by": user["_id"],
        "created_at": _now(),
        "updated_at": _now(),
    }
    inserted_id = _collection("project").insert_one(doc).inserted_id
    return {"id": str(inserted_id), "number": number, **payload.model_dump()}


@app.get("/projects", response_model=List[ProjectOut])
async def list_projects(user = Depends(get_current_user)):
    docs = _collection("project").find().sort("created_at", -1)
    items: List[ProjectOut] = []  # type: ignore
    for d in docs:
        items.append(ProjectOut(
            id=str(d["_id"]),
            number=d.get("number", 0),
            title=d.get("title", ""),
            client=d.get("client", ""),
            status=d.get("status", "active"),
            manager_id=d.get("manager_id"),
            engineer_ids=d.get("engineer_ids", []),
        ))
    return items


@app.get("/projects/{project_id}", response_model=ProjectOut)
async def get_project(project_id: str, user = Depends(get_current_user)):
    from bson import ObjectId
    d = _collection("project").find_one({"_id": ObjectId(project_id)})
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    return ProjectOut(
        id=str(d["_id"]),
        number=d.get("number", 0),
        title=d.get("title", ""),
        client=d.get("client", ""),
        status=d.get("status", "active"),
        manager_id=d.get("manager_id"),
        engineer_ids=d.get("engineer_ids", []),
    )


# ----------------------
# Expenses (skeleton endpoints for MVP)
# ----------------------
class ExpenseIn(BaseModel):
    project_id: str
    amount: float
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    description: Optional[str] = None

class ExpenseOut(ExpenseIn):
    id: str
    status: str
    requested_by: str
    approvals: List[Dict[str, Any]]


@app.post("/expenses", response_model=ExpenseOut)
async def create_expense(payload: ExpenseIn, user = Depends(require_roles("Engineer", "Manager", "Admin"))):
    doc = {
        **payload.model_dump(),
        "status": "pending_manager",
        "requested_by": user["_id"],
        "approvals": [],
        "created_at": _now(),
        "updated_at": _now(),
    }
    inserted_id = _collection("expense").insert_one(doc).inserted_id
    return ExpenseOut(id=str(inserted_id), approvals=[], status=doc["status"], requested_by=user["_id"], **payload.model_dump())


class ApproveBody(BaseModel):
    action: str = Field(pattern=r"^(approve|reject)$")
    note: Optional[str] = None


@app.post("/expenses/{expense_id}/approve", response_model=ExpenseOut)
async def approve_expense(expense_id: str, body: ApproveBody, user = Depends(get_current_user)):
    from bson import ObjectId
    exp = _collection("expense").find_one({"_id": ObjectId(expense_id)})
    if not exp:
        raise HTTPException(status_code=404, detail="Expense not found")

    role = user["role"]
    status = exp.get("status")

    # Approval flow: Engineer -> Manager -> Accountant
    if status == "pending_manager" and role not in {"Manager", "Admin"}:
        raise HTTPException(status_code=403, detail="Manager approval required")
    if status == "pending_accountant" and role not in {"Accountant", "Admin"}:
        raise HTTPException(status_code=403, detail="Accountant approval required")

    new_status = status
    if body.action == "reject":
        new_status = "rejected"
    else:
        if status == "pending_manager":
            new_status = "pending_accountant"
        elif status == "pending_accountant":
            new_status = "approved"

    approval_entry = {
        "by": user["_id"],
        "role": role,
        "action": body.action,
        "note": body.note,
        "at": _now(),
    }

    _collection("expense").update_one(
        {"_id": ObjectId(expense_id)},
        {"$set": {"status": new_status, "updated_at": _now()}, "$push": {"approvals": approval_entry}}
    )

    exp = _collection("expense").find_one({"_id": ObjectId(expense_id)})
    return ExpenseOut(
        id=str(exp["_id"]),
        project_id=exp["project_id"],
        amount=float(exp["amount"]),
        currency=exp["currency"],
        description=exp.get("description"),
        status=exp["status"],
        requested_by=exp["requested_by"],
        approvals=exp.get("approvals", []),
    )


@app.get("/expenses", response_model=List[ExpenseOut])
async def list_expenses(user = Depends(get_current_user)):
    items: List[ExpenseOut] = []  # type: ignore
    for exp in _collection("expense").find().sort("created_at", -1):
        items.append(ExpenseOut(
            id=str(exp["_id"]),
            project_id=exp["project_id"],
            amount=float(exp["amount"]),
            currency=exp["currency"],
            description=exp.get("description"),
            status=exp["status"],
            requested_by=exp["requested_by"],
            approvals=exp.get("approvals", []),
        ))
    return items


# ----------------------
# Team / Leaves (skeleton)
# ----------------------
class LeaveIn(BaseModel):
    start_date: str
    end_date: str
    reason: Optional[str] = None

class LeaveOut(LeaveIn):
    id: str
    status: str
    user_id: str


@app.post("/leaves", response_model=LeaveOut)
async def request_leave(payload: LeaveIn, user = Depends(require_roles("Engineer", "Manager", "Admin", "Accountant"))):
    doc = {
        **payload.model_dump(),
        "status": "pending_manager",
        "user_id": user["_id"],
        "created_at": _now(),
        "updated_at": _now(),
    }
    inserted_id = _collection("leave").insert_one(doc).inserted_id
    return LeaveOut(id=str(inserted_id), status=doc["status"], user_id=user["_id"], **payload.model_dump())


@app.post("/leaves/{leave_id}/approve", response_model=LeaveOut)
async def approve_leave(leave_id: str, body: ApproveBody, user = Depends(require_roles("Manager", "Admin"))):
    from bson import ObjectId
    leave = _collection("leave").find_one({"_id": ObjectId(leave_id)})
    if not leave:
        raise HTTPException(status_code=404, detail="Leave not found")
    new_status = "approved" if body.action == "approve" else "rejected"
    _collection("leave").update_one({"_id": ObjectId(leave_id)}, {"$set": {"status": new_status, "updated_at": _now()}})
    leave = _collection("leave").find_one({"_id": ObjectId(leave_id)})
    return LeaveOut(id=str(leave["_id"]), status=leave["status"], user_id=leave["user_id"], start_date=leave["start_date"], end_date=leave["end_date"], reason=leave.get("reason"))


# ----------------------
# Documents (skeleton)
# ----------------------
class DocumentIn(BaseModel):
    project_id: str
    type: str = Field(pattern=r"^(daily_report|drawing|contract|safety)$")
    title: str
    url: Optional[str] = None

class DocumentOut(DocumentIn):
    id: str
    created_by: str


@app.post("/documents", response_model=DocumentOut)
async def create_document(payload: DocumentIn, user = Depends(require_roles("Engineer", "Manager", "Admin"))):
    doc = {
        **payload.model_dump(),
        "created_by": user["_id"],
        "created_at": _now(),
        "updated_at": _now(),
    }
    inserted_id = _collection("document").insert_one(doc).inserted_id
    return DocumentOut(id=str(inserted_id), created_by=user["_id"], **payload.model_dump())


@app.get("/documents", response_model=List[DocumentOut])
async def list_documents(project_id: Optional[str] = None, user = Depends(get_current_user)):
    query: Dict[str, Any] = {}
    if project_id:
        query["project_id"] = project_id
    items: List[DocumentOut] = []  # type: ignore
    for d in _collection("document").find(query).sort("created_at", -1):
        items.append(DocumentOut(
            id=str(d["_id"]),
            project_id=d["project_id"],
            type=d["type"],
            title=d["title"],
            url=d.get("url"),
            created_by=d["created_by"],
        ))
    return items


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
