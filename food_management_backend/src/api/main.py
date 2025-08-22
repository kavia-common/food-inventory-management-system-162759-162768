import os
from datetime import datetime, timedelta, date
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext

# Note on configuration:
# This application expects certain environment variables to be set at runtime.
# If they are missing, default values are used for development convenience.
# For production, please set the appropriate env vars in the .env file managed by the orchestrator.

# -----------------------------
# App and Security configuration
# -----------------------------
APP_TITLE = "Food Inventory Management API"
APP_DESCRIPTION = (
    "Backend service for managing food inventory, authentication, expiry notifications, and reporting. "
    "Includes CRUD operations for food items, user signup/login, and aggregated reporting data."
)
APP_VERSION = "1.0.0"

# Environment-driven secrets (do not hardcode in code, but provide safe defaults for local dev)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Database dependency placeholders:
# In a real integrated environment, you would connect to the food_management_database using env vars like:
# FOOD_DB_URL, FOOD_DB_USER, FOOD_DB_PASSWORD, FOOD_DB_NAME, FOOD_DB_PORT
# Here, for the sake of this backend container, we implement an in-memory repository abstraction that can be
# swapped with a real DB-backed repository later. The interface is clean and separated.
# Mandatory note: Ensure these env vars are configured when integrating with the database container.

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    openapi_tags=[
        {"name": "Health", "description": "Service health and information."},
        {"name": "Auth", "description": "User signup, login, and authentication."},
        {"name": "Food", "description": "CRUD and search endpoints for food inventory."},
        {"name": "Notifications", "description": "Expiry notifications and reminders."},
        {"name": "Reports", "description": "Aggregated reporting endpoints."},
    ],
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Models
# -----------------------------
class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Token type, typically 'bearer'")


class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    full_name: Optional[str] = Field(None, description="User's full name")


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Plain text password for signup")


class User(UserBase):
    id: str = Field(..., description="Unique user identifier")


class UserInDB(User):
    hashed_password: str = Field(..., description="Hashed user password")


class FoodBase(BaseModel):
    name: str = Field(..., description="Name of the food item")
    quantity: float = Field(..., description="Quantity of the food item (units depend on unit)")
    unit: str = Field(..., description="Unit of measurement (e.g., kg, g, l, ml, pcs)")
    expiry_date: Optional[date] = Field(None, description="Expiry date of the item (YYYY-MM-DD)")
    category: Optional[str] = Field(None, description="Category, e.g., 'Dairy', 'Vegetables'")
    location: Optional[str] = Field(None, description="Storage location, e.g., 'Fridge', 'Pantry'")
    notes: Optional[str] = Field(None, description="Additional notes or description")


class FoodCreate(FoodBase):
    pass


class FoodUpdate(BaseModel):
    name: Optional[str] = Field(None, description="Name of the food item")
    quantity: Optional[float] = Field(None, description="Quantity of the food item")
    unit: Optional[str] = Field(None, description="Unit of measurement")
    expiry_date: Optional[date] = Field(None, description="Expiry date of the item (YYYY-MM-DD)")
    category: Optional[str] = Field(None, description="Category")
    location: Optional[str] = Field(None, description="Storage location")
    notes: Optional[str] = Field(None, description="Additional notes or description")


class Food(FoodBase):
    id: str = Field(..., description="Unique identifier for the food item")
    owner_id: str = Field(..., description="Identifier of the user who owns this item")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class ExpiryNotification(BaseModel):
    id: str = Field(..., description="Unique identifier for the notification")
    food_id: str = Field(..., description="Related food item id")
    owner_id: str = Field(..., description="User id of owner")
    message: str = Field(..., description="Human readable notification message")
    due_date: date = Field(..., description="The date when the item is due/expiring")
    created_at: datetime = Field(..., description="Creation timestamp")
    acknowledged: bool = Field(..., description="Whether the user acknowledged the notification")


class ReportSummary(BaseModel):
    total_items: int = Field(..., description="Total count of items")
    items_by_category: Dict[str, int] = Field(..., description="Count of items grouped by category")
    items_expiring_within_7_days: int = Field(..., description="How many items expiring within 7 days")
    expired_items: int = Field(..., description="How many items already expired")
    total_quantity_by_unit: Dict[str, float] = Field(..., description="Aggregated quantity grouped by unit")


# -----------------------------
# Simple in-memory "repository"
# -----------------------------
# This is a placeholder for a real database repository. Replace with DB integration later.
from uuid import uuid4


class InMemoryDB:
    def __init__(self):
        self.users: Dict[str, UserInDB] = {}
        self.users_by_email: Dict[str, str] = {}
        self.foods: Dict[str, Food] = {}
        self.notifications: Dict[str, ExpiryNotification] = {}

    # User operations
    def create_user(self, email: str, full_name: Optional[str], hashed_password: str) -> UserInDB:
        if email in self.users_by_email:
            raise ValueError("User already exists")
        user_id = str(uuid4())
        user = UserInDB(id=user_id, email=email, full_name=full_name, hashed_password=hashed_password)
        self.users[user_id] = user
        self.users_by_email[email] = user_id
        return user

    def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        uid = self.users_by_email.get(email)
        if not uid:
            return None
        return self.users.get(uid)

    def get_user(self, user_id: str) -> Optional[UserInDB]:
        return self.users.get(user_id)

    # Food operations
    def create_food(self, owner_id: str, data: FoodCreate) -> Food:
        fid = str(uuid4())
        now = datetime.utcnow()
        food = Food(
            id=fid,
            owner_id=owner_id,
            created_at=now,
            updated_at=now,
            **data.model_dump(),
        )
        self.foods[fid] = food
        return food

    def get_food(self, food_id: str) -> Optional[Food]:
        return self.foods.get(food_id)

    def list_foods(
        self,
        owner_id: str,
        q: Optional[str] = None,
        category: Optional[str] = None,
        location: Optional[str] = None,
        expiring_before: Optional[date] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Food]:
        items = [f for f in self.foods.values() if f.owner_id == owner_id]
        if q:
            q_lower = q.lower()
            items = [f for f in items if q_lower in f.name.lower()]
        if category:
            items = [f for f in items if (f.category or "").lower() == category.lower()]
        if location:
            items = [f for f in items if (f.location or "").lower() == location.lower()]
        if expiring_before:
            items = [f for f in items if f.expiry_date is not None and f.expiry_date <= expiring_before]
        items.sort(key=lambda x: (x.expiry_date or date.max, x.name.lower()))
        return items[skip : skip + limit]

    def update_food(self, food_id: str, data: FoodUpdate) -> Optional[Food]:
        existing = self.foods.get(food_id)
        if not existing:
            return None
        updates = data.model_dump(exclude_unset=True)
        for k, v in updates.items():
            setattr(existing, k, v)
        existing.updated_at = datetime.utcnow()
        self.foods[food_id] = existing
        return existing

    def delete_food(self, food_id: str) -> bool:
        if food_id in self.foods:
            del self.foods[food_id]
            return True
        return False

    # Notification operations
    def create_notification(self, owner_id: str, food_id: str, message: str, due_date: date) -> ExpiryNotification:
        nid = str(uuid4())
        now = datetime.utcnow()
        notif = ExpiryNotification(
            id=nid,
            food_id=food_id,
            owner_id=owner_id,
            message=message,
            due_date=due_date,
            created_at=now,
            acknowledged=False,
        )
        self.notifications[nid] = notif
        return notif

    def list_notifications(self, owner_id: str, only_pending: bool = True) -> List[ExpiryNotification]:
        items = [n for n in self.notifications.values() if n.owner_id == owner_id]
        if only_pending:
            items = [n for n in items if not n.acknowledged]
        items.sort(key=lambda n: (n.due_date, n.created_at))
        return items

    def acknowledge_notification(self, notification_id: str, owner_id: str) -> Optional[ExpiryNotification]:
        notif = self.notifications.get(notification_id)
        if not notif or notif.owner_id != owner_id:
            return None
        notif.acknowledged = True
        self.notifications[notification_id] = notif
        return notif


db = InMemoryDB()


# -----------------------------
# Security helpers
# -----------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """Retrieve the current authenticated user from a JWT bearer token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.get_user(user_id)
    if user is None:
        raise credentials_exception
    return user


# -----------------------------
# Health
# -----------------------------
@app.get("/", tags=["Health"], summary="Health Check", operation_id="health_check")
def health_check() -> Dict[str, str]:
    """Health check endpoint to verify the API is reachable.
    Returns a simple message payload indicating service health.
    """
    return {"message": "Healthy"}


# -----------------------------
# Auth endpoints
# -----------------------------
# PUBLIC_INTERFACE
@app.post(
    "/auth/signup",
    response_model=User,
    status_code=201,
    tags=["Auth"],
    summary="User Signup",
    description="Create a new user account with email, full name, and password.",
)
def signup(user: UserCreate) -> User:
    """Create a new user account.
    Parameters:
      - user: UserCreate with email, full_name, password
    Returns:
      - User: the created user without password
    """
    # Ensure unique email and create user
    existing = db.get_user_by_email(user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user.password)
    created = db.create_user(user.email, user.full_name, hashed)
    return User(id=created.id, email=created.email, full_name=created.full_name)


# PUBLIC_INTERFACE
@app.post(
    "/auth/token",
    response_model=Token,
    tags=["Auth"],
    summary="Obtain Access Token",
    description="Obtain a JWT bearer token using OAuth2 password flow.",
)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """Login to obtain a JWT token using username (email) and password.
    Parameters:
      - form_data: OAuth2PasswordRequestForm, where username is email
    Returns:
      - Token: bearer token for Authorization header
    """
    user = db.get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": user.id}, expires_delta=access_token_expires)
    return Token(access_token=token, token_type="bearer")


# -----------------------------
# Food CRUD endpoints
# -----------------------------
# PUBLIC_INTERFACE
@app.post(
    "/food",
    response_model=Food,
    status_code=201,
    tags=["Food"],
    summary="Create Food Item",
    description="Create a new food item for the authenticated user.",
)
def create_food(food: FoodCreate, current_user: UserInDB = Depends(get_current_user)) -> Food:
    """Create a food item owned by the current user."""
    created = db.create_food(current_user.id, food)
    # Auto-create a notification if expiry is within N days
    _maybe_create_expiry_notification(created)
    return created


# PUBLIC_INTERFACE
@app.get(
    "/food",
    response_model=List[Food],
    tags=["Food"],
    summary="List Food Items",
    description="List food items owned by the current user with optional filters and pagination.",
)
def list_food(
    q: Optional[str] = Query(None, description="Search term on name"),
    category: Optional[str] = Query(None, description="Filter by category"),
    location: Optional[str] = Query(None, description="Filter by storage location"),
    expiring_before: Optional[date] = Query(None, description="Filter by expiry date upper bound (YYYY-MM-DD)"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Pagination limit"),
    current_user: UserInDB = Depends(get_current_user),
) -> List[Food]:
    """List food items for the current user."""
    return db.list_foods(
        owner_id=current_user.id,
        q=q,
        category=category,
        location=location,
        expiring_before=expiring_before,
        skip=skip,
        limit=limit,
    )


# PUBLIC_INTERFACE
@app.get(
    "/food/{food_id}",
    response_model=Food,
    tags=["Food"],
    summary="Get Food Item",
    description="Retrieve a single food item by id if owned by the current user.",
)
def get_food(
    food_id: str = Path(..., description="ID of the food item"),
    current_user: UserInDB = Depends(get_current_user),
) -> Food:
    """Retrieve a food item by id."""
    food = db.get_food(food_id)
    if not food or food.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Food item not found")
    return food


# PUBLIC_INTERFACE
@app.patch(
    "/food/{food_id}",
    response_model=Food,
    tags=["Food"],
    summary="Update Food Item",
    description="Partially update a food item by id if owned by the current user.",
)
def update_food(
    food_id: str,
    data: FoodUpdate,
    current_user: UserInDB = Depends(get_current_user),
) -> Food:
    """Update a food item by id."""
    existing = db.get_food(food_id)
    if not existing or existing.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Food item not found")
    updated = db.update_food(food_id, data)
    if updated is None:
        raise HTTPException(status_code=404, detail="Food item not found")
    # Check for new expiry notification if date changed or newly set
    _maybe_create_expiry_notification(updated)
    return updated


# PUBLIC_INTERFACE
@app.delete(
    "/food/{food_id}",
    status_code=204,
    tags=["Food"],
    summary="Delete Food Item",
    description="Delete a food item by id if owned by the current user.",
)
def delete_food(
    food_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> None:
    """Delete a food item by id."""
    existing = db.get_food(food_id)
    if not existing or existing.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Food item not found")
    db.delete_food(food_id)
    return None


# -----------------------------
# Expiry Notifications
# -----------------------------
EXPIRY_THRESHOLD_DAYS = int(os.getenv("EXPIRY_THRESHOLD_DAYS", "7"))


def _maybe_create_expiry_notification(food: Food) -> None:
    """Create a notification if the food item expiry is within the threshold."""
    if food.expiry_date:
        today = date.today()
        if today <= food.expiry_date <= today + timedelta(days=EXPIRY_THRESHOLD_DAYS):
            msg = f"'{food.name}' is expiring on {food.expiry_date.isoformat()}."
            db.create_notification(owner_id=food.owner_id, food_id=food.id, message=msg, due_date=food.expiry_date)


class NotificationAckRequest(BaseModel):
    acknowledged: bool = Field(..., description="Set true to acknowledge notification")


# PUBLIC_INTERFACE
@app.get(
    "/notifications",
    response_model=List[ExpiryNotification],
    tags=["Notifications"],
    summary="List Notifications",
    description="List expiry notifications for the current user. Only pending by default.",
)
def list_expiry_notifications(
    only_pending: bool = Query(True, description="Filter only pending (unacknowledged) notifications"),
    current_user: UserInDB = Depends(get_current_user),
) -> List[ExpiryNotification]:
    """List expiry notifications owned by the current user."""
    return db.list_notifications(owner_id=current_user.id, only_pending=only_pending)


# PUBLIC_INTERFACE
@app.post(
    "/notifications/{notification_id}/ack",
    response_model=ExpiryNotification,
    tags=["Notifications"],
    summary="Acknowledge Notification",
    description="Acknowledge a specific notification by id.",
)
def acknowledge_notification(
    notification_id: str = Path(..., description="Notification id"),
    body: NotificationAckRequest = None,
    current_user: UserInDB = Depends(get_current_user),
) -> ExpiryNotification:
    """Acknowledge a notification by id."""
    updated = db.acknowledge_notification(notification_id, owner_id=current_user.id)
    if not updated:
        raise HTTPException(status_code=404, detail="Notification not found")
    return updated


# -----------------------------
# Reports
# -----------------------------
# PUBLIC_INTERFACE
@app.get(
    "/reports/summary",
    response_model=ReportSummary,
    tags=["Reports"],
    summary="Summary Report",
    description="Return a summary report with totals, groupings, and expiry stats for the current user.",
)
def get_summary_report(current_user: UserInDB = Depends(get_current_user)) -> ReportSummary:
    """Generate a summary report for the current user's inventory."""
    items = db.list_foods(owner_id=current_user.id, limit=10_000)
    total_items = len(items)

    # Group by category
    items_by_category: Dict[str, int] = {}
    for it in items:
        cat = (it.category or "Uncategorized").strip() or "Uncategorized"
        items_by_category[cat] = items_by_category.get(cat, 0) + 1

    # Expiry windows
    today = date.today()
    within_7 = 0
    expired = 0
    for it in items:
        if it.expiry_date:
            if it.expiry_date < today:
                expired += 1
            elif it.expiry_date <= today + timedelta(days=7):
                within_7 += 1

    # Aggregate quantities by unit
    total_quantity_by_unit: Dict[str, float] = {}
    for it in items:
        unit = (it.unit or "").strip() or "unit"
        total_quantity_by_unit[unit] = total_quantity_by_unit.get(unit, 0.0) + float(it.quantity or 0.0)

    return ReportSummary(
        total_items=total_items,
        items_by_category=items_by_category,
        items_expiring_within_7_days=within_7,
        expired_items=expired,
        total_quantity_by_unit=total_quantity_by_unit,
    )


# -----------------------------
# WebSocket (Documentation helper)
# -----------------------------
@app.get(
    "/docs/websocket",
    tags=["Health"],
    summary="WebSocket Usage",
    description="Documentation placeholder for real-time updates. This project currently does not expose a WebSocket, "
                "but if added in the future, the usage guide will be placed here.",
)
def websocket_usage() -> Dict[str, Any]:
    """Provide info about potential WebSocket endpoints (not implemented)."""
    return {
        "message": "No WebSocket endpoints are currently implemented. Future versions may add real-time updates.",
        "endpoints": [],
    }
