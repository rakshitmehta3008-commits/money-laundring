
import os
import datetime
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP, ForeignKey, DECIMAL, TEXT, BOOLEAN, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
SQLALCHEMY_DATABASE_URL = "sqlite:///./phonesecurity.db"
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
oauth2_admin_scheme = OAuth2PasswordBearer(tokenUrl="/api/admin/auth/login")

class EndUser(Base):
    __tablename__ = "EndUser"
    user_id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

    reports = relationship("Report", back_populates="user")
    consents = relationship("UserConsent", back_populates="user")
    screened_calls = relationship("ScreenedCall", back_populates="user")

class PhoneNumber(Base):
    __tablename__ = "PhoneNumber"
    phone_number_id = Column(Integer, primary_key=True, index=True)
    number = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, nullable=False)
    ai_fraud_score = Column(DECIMAL(5, 4))
    threat_category = Column(String)
    last_checked_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

class Administrator(Base):
    __tablename__ = "Administrator"
    admin_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

class APIPartner(Base):
    __tablename__ = "API_Partner"
    partner_id = Column(Integer, primary_key=True, index=True)
    organization_name = Column(String, nullable=False)
    api_key = Column(String, unique=True, nullable=False)
    status = Column(String, nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

class Report(Base):
    __tablename__ = "Report"
    report_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("EndUser.user_id"), nullable=False)
    phone_number_id = Column(Integer, ForeignKey("PhoneNumber.phone_number_id"), nullable=False)
    report_details = Column(TEXT)
    submitted_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

    user = relationship("EndUser", back_populates="reports")
    phone_number = relationship("PhoneNumber")

class Appeal(Base):
    __tablename__ = "Appeal"
    appeal_id = Column(Integer, primary_key=True, index=True)
    phone_number_id = Column(Integer, ForeignKey("PhoneNumber.phone_number_id"), nullable=False)
    submitter_contact = Column(String, nullable=False)
    appeal_reason = Column(TEXT, nullable=False)
    status = Column(String, nullable=False)
    reviewed_by_admin_id = Column(Integer, ForeignKey("Administrator.admin_id"))
    submitted_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)
    reviewed_at = Column(TIMESTAMP)

    phone_number = relationship("PhoneNumber")

class AuditLog(Base):
    __tablename__ = "AuditLog"
    log_id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("Administrator.admin_id"), nullable=False)
    action = Column(String, nullable=False)
    target_entity_type = Column(String)
    target_entity_id = Column(Integer)
    details = Column(TEXT)
    action_timestamp = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

class UserConsent(Base):
    __tablename__ = "UserConsent"
    consent_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("EndUser.user_id"), nullable=False)
    consent_type = Column(String, nullable=False)
    status = Column(String, nullable=False)
    last_updated_at = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)

    user = relationship("EndUser", back_populates="consents")

class ScreenedCall(Base):
    __tablename__ = "ScreenedCall"
    call_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("EndUser.user_id"), nullable=False)
    phone_number_id = Column(Integer, ForeignKey("PhoneNumber.phone_number_id"), nullable=False)
    call_timestamp = Column(TIMESTAMP, nullable=False, default=datetime.datetime.utcnow)
    action_taken = Column(String)
    alert_displayed = Column(BOOLEAN, nullable=False)

    user = relationship("EndUser", back_populates="screened_calls")
    phone_number = relationship("PhoneNumber")

Base.metadata.create_all(bind=engine)

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None

class User(UserBase):
    user_id: int
    created_at: datetime.datetime

    class Config:
        orm_mode = True

class UserWithToken(User):
    authToken: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    sub: Optional[str] = None 
class ConsentBase(BaseModel):
    consent_type: str
    status: str

class ConsentUpdate(ConsentBase):
    pass

class UserConsent(ConsentBase):
    consent_id: int
    last_updated_at: datetime.datetime

    class Config:
        orm_mode = True

class PhoneNumberBase(BaseModel):
    number: str
    status: str
    ai_fraud_score: Optional[float] = None
    threat_category: Optional[str] = None

class PhoneNumberLookup(PhoneNumberBase):
    pass

class PhoneNumberAdmin(PhoneNumberBase):
    phone_number_id: int
    last_checked_at: Optional[datetime.datetime]
    created_at: datetime.datetime

    class Config:
        orm_mode = True

class ReportCreate(BaseModel):
    number: str
    report_details: Optional[str] = None

class ReportResponse(BaseModel):
    report_id: int
    status_message: str

class ReportFull(BaseModel):
    report_id: int
    user_id: int
    phone_number_id: int
    report_details: Optional[str]
    submitted_at: datetime.datetime

    class Config:
        orm_mode = True

class PhoneNumberWithReports(PhoneNumberAdmin):
    reports: List[ReportFull] = []

class ScreenedCallCreate(BaseModel):
    number: str
    action_taken: Optional[str]
    alert_displayed: bool

class ScreenedCallResponse(BaseModel):
    call_id: int

class ScreenedCallHistory(BaseModel):
    call_id: int
    call_timestamp: datetime.datetime
    action_taken: Optional[str]
    alert_displayed: bool
    phone_number: PhoneNumberBase

    class Config:
        orm_mode = True

class AppealCreate(BaseModel):
    number: str
    submitter_contact: str
    appeal_reason: str

class AppealResponse(BaseModel):
    appeal_id: int
    status: str

class AppealAdmin(AppealResponse):
    phone_number_id: int
    submitter_contact: str
    appeal_reason: str
    submitted_at: datetime.datetime
    reviewed_at: Optional[datetime.datetime]

    class Config:
        orm_mode = True
class APIPartnerCreate(BaseModel):
    organization_name: str

class APIPartnerUpdate(APIPartnerCreate):
    status: str

class APIPartner(APIPartnerUpdate):
    partner_id: int
    api_key: str
    created_at: datetime.datetime

    class Config:
        orm_mode = True

class APIPartnerWithNewKey(APIPartnerCreate):
    partner_id: int
    api_key: str
    status: str
    created_at: datetime.datetime
    class Config:
        orm_mode = True

class AuditLogEntry(BaseModel):
    log_id: int
    admin_id: int
    action: str
    target_entity_type: Optional[str]
    target_entity_id: Optional[int]
    details: Optional[str]
    action_timestamp: datetime.datetime

    class Config:
        orm_mode = True

class AnalyticsSummary(BaseModel):
    trend_data: Dict[str, Any]
    geographical_hotspots: Dict[str, Any]

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None or payload.get("type") != 'user':
            raise credentials_exception
        token_data = TokenData(sub=email)
    except JWTError:
        raise credentials_exception
    user = db.query(EndUser).filter(EndUser.email == token_data.sub).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_admin(token: str = Depends(oauth2_admin_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate admin credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or payload.get("type") != 'admin':
            raise credentials_exception
        token_data = TokenData(sub=username)
    except JWTError:
        raise credentials_exception
    admin = db.query(Administrator).filter(Administrator.username == token_data.sub).first()
    if admin is None:
        raise credentials_exception
    return admin

async def get_current_user_or_partner(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):

    try:
        return get_current_user(token, db)
    except HTTPException as user_exc:
        if user_exc.status_code != 401:
            raise user_exc
        
    partner = db.query(APIPartner).filter(APIPartner.api_key == token, APIPartner.status == 'active').first()
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid authentication credentials"
        )
    return partner



def create_audit_log(db: Session, admin_id: int, action: str, details: str = None, target_entity_type: str = None, target_entity_id: int = None):
    db_log = AuditLog(
        admin_id=admin_id,
        action=action,
        details=details,
        target_entity_type=target_entity_type,
        target_entity_id=target_entity_id
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


def get_or_create_phone_number(db: Session, number: str):
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.number == number).first()
    if not db_phone:
        db_phone = PhoneNumber(number=number, status="pending_review")
        db.add(db_phone)
        db.commit()
        db.refresh(db_phone)
    return db_phone


app = FastAPI(title="Phone Security API")


user_router = FastAPI()

@user_router.post("/api/users/register", response_model=UserWithToken, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(EndUser).filter(EndUser.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = EndUser(email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email, "type": "user"}, expires_delta=access_token_expires
    )
    return {"user_id": db_user.user_id, "email": db_user.email, "created_at": db_user.created_at, "authToken": access_token}

@user_router.post("/api/auth/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(EndUser).filter(EndUser.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "type": "user"}, expires_delta=access_token_expires
    )
    return {"authToken": access_token, "user_id": user.user_id}

@user_router.get("/api/users/me", response_model=User)
def read_users_me(current_user: EndUser = Depends(get_current_user)):
    return current_user

@user_router.put("/api/users/me", response_model=User)
def update_user_me(user_update: UserUpdate, db: Session = Depends(get_db), current_user: EndUser = Depends(get_current_user)):
    if user_update.email:
        existing_user = db.query(EndUser).filter(EndUser.email == user_update.email).first()
        if existing_user and existing_user.user_id != current_user.user_id:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = user_update.email
    if user_update.password:
        current_user.password_hash = get_password_hash(user_update.password)
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user

@user_router.get("/api/users/me/consents", response_model=List[UserConsent])
def get_user_consents(current_user: EndUser = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(UserConsent).filter(UserConsent.user_id == current_user.user_id).all()

@user_router.put("/api/users/me/consents", response_model=List[UserConsent])
def update_user_consents(consents: List[ConsentUpdate], current_user: EndUser = Depends(get_current_user), db: Session = Depends(get_db)):
    updated_consents = []
    for consent_update in consents:
        db_consent = db.query(UserConsent).filter(
            UserConsent.user_id == current_user.user_id, 
            UserConsent.consent_type == consent_update.consent_type
        ).first()
        if db_consent:
            db_consent.status = consent_update.status
            db_consent.last_updated_at = datetime.datetime.utcnow()
        else:
            db_consent = UserConsent(
                user_id=current_user.user_id,
                consent_type=consent_update.consent_type,
                status=consent_update.status
            )
            db.add(db_consent)
        db.commit()
        db.refresh(db_consent)
        updated_consents.append(db_consent)
    return updated_consents

@user_router.get("/api/lookup/{phoneNumber}", response_model=PhoneNumberLookup)
def lookup_phone_number(phoneNumber: str, db: Session = Depends(get_db), auth: Any = Depends(get_current_user_or_partner)):
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.number == phoneNumber).first()
    if not db_phone:
        raise HTTPException(status_code=404, detail="Phone number not found in database")
    db_phone.last_checked_at = datetime.datetime.utcnow()
    db.commit()
    return db_phone

@user_router.post("/api/reports", response_model=ReportResponse)
def create_report(report: ReportCreate, db: Session = Depends(get_db), current_user: EndUser = Depends(get_current_user)):
    db_phone = get_or_create_phone_number(db, report.number)
    db_report = Report(
        user_id=current_user.user_id,
        phone_number_id=db_phone.phone_number_id,
        report_details=report.report_details
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return {"report_id": db_report.report_id, "status_message": "Report submitted successfully."}

@user_router.get("/api/users/me/history", response_model=List[ScreenedCallHistory])
def get_user_history(current_user: EndUser = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ScreenedCall).filter(ScreenedCall.user_id == current_user.user_id).order_by(ScreenedCall.call_timestamp.desc()).all()

@user_router.post("/api/screened-calls", response_model=ScreenedCallResponse)
def log_screened_call(call: ScreenedCallCreate, db: Session = Depends(get_db), current_user: EndUser = Depends(get_current_user)):
    db_phone = get_or_create_phone_number(db, call.number)
    db_call = ScreenedCall(
        user_id=current_user.user_id,
        phone_number_id=db_phone.phone_number_id,
        action_taken=call.action_taken,
        alert_displayed=call.alert_displayed
    )
    db.add(db_call)
    db.commit()
    db.refresh(db_call)
    return {"call_id": db_call.call_id}

@user_router.post("/api/appeals", response_model=AppealResponse)
def submit_appeal(appeal: AppealCreate, db: Session = Depends(get_db)):
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.number == appeal.number).first()
    if not db_phone:
        raise HTTPException(status_code=404, detail="Phone number not found. Cannot submit appeal for unlisted number.")
    
    db_appeal = Appeal(
        phone_number_id=db_phone.phone_number_id,
        submitter_contact=appeal.submitter_contact,
        appeal_reason=appeal.appeal_reason,
        status="pending_review"
    )
    db.add(db_appeal)
    db.commit()
    db.refresh(db_appeal)
    return {"appeal_id": db_appeal.appeal_id, "status": db_appeal.status}


admin_router = FastAPI()

@admin_router.post("/api/admin/auth/login")
def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    admin = db.query(Administrator).filter(Administrator.username == form_data.username).first()
    if not admin or not verify_password(form_data.password, admin.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": admin.username, "type": "admin"})
    return {"access_token": access_token, "token_type": "bearer"}


@admin_router.get("/api/admin/phonenumbers/pending", response_model=List[PhoneNumberAdmin])
def get_pending_phone_numbers(db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    return db.query(PhoneNumber).filter(PhoneNumber.status == 'pending_review').all()

@admin_router.get("/api/admin/phonenumbers/{id}", response_model=PhoneNumberWithReports)
def get_phone_number_details(id: int, db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.phone_number_id == id).first()
    if not db_phone:
        raise HTTPException(status_code=404, detail="Phone number not found")
    reports = db.query(Report).filter(Report.phone_number_id == id).all()
    return PhoneNumberWithReports(**db_phone.__dict__, reports=reports)

@admin_router.post("/api/admin/phonenumbers/{id}/approve", response_model=PhoneNumberAdmin)
def approve_phone_number(
    id: int, 
    threat_category: str, 
    justification_notes: str, 
    db: Session = Depends(get_db), 
    current_admin: Administrator = Depends(get_current_admin)
):
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.phone_number_id == id).first()
    if not db_phone:
        raise HTTPException(status_code=404, detail="Phone number not found")
    db_phone.status = 'approved'
    db_phone.threat_category = threat_category
    db.commit()
    create_audit_log(db, current_admin.admin_id, 'approve_phone_number', justification_notes, 'PhoneNumber', id)
    db.refresh(db_phone)
    return db_phone

@admin_router.post("/api/admin/phonenumbers/{id}/reject", response_model=PhoneNumberAdmin)
def reject_phone_number(id: int, justification_notes: str, db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.phone_number_id == id).first()
    if not db_phone:
        raise HTTPException(status_code=404, detail="Phone number not found")
    db_phone.status = 'rejected_safe'
    db.commit()
    create_audit_log(db, current_admin.admin_id, 'reject_phone_number', justification_notes, 'PhoneNumber', id)
    db.refresh(db_phone)
    return db_phone

@admin_router.get("/api/admin/appeals/pending", response_model=List[AppealAdmin])
def get_pending_appeals(db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    return db.query(Appeal).filter(Appeal.status == 'pending_review').all()

@admin_router.post("/api/admin/appeals/{id}/approve", response_model=AppealAdmin)
def approve_appeal(id: int, db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    db_appeal = db.query(Appeal).filter(Appeal.appeal_id == id).first()
    if not db_appeal:
        raise HTTPException(status_code=404, detail="Appeal not found")
    db_appeal.status = 'approved'
    db_appeal.reviewed_by_admin_id = current_admin.admin_id
    db_appeal.reviewed_at = datetime.datetime.utcnow()
    db_phone = db.query(PhoneNumber).filter(PhoneNumber.phone_number_id == db_appeal.phone_number_id).first()
    if db_phone:
        db_phone.status = 'safe_after_appeal'
    db.commit()
    create_audit_log(db, current_admin.admin_id, 'approve_appeal', target_entity_type='Appeal', target_entity_id=id)
    db.refresh(db_appeal)
    return db_appeal

@admin_router.post("/api/admin/appeals/{id}/reject", response_model=AppealAdmin)
def reject_appeal(id: int, db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    db_appeal = db.query(Appeal).filter(Appeal.appeal_id == id).first()
    if not db_appeal:
        raise HTTPException(status_code=404, detail="Appeal not found")
    db_appeal.status = 'rejected'
    db_appeal.reviewed_by_admin_id = current_admin.admin_id
    db_appeal.reviewed_at = datetime.datetime.utcnow()
    db.commit()
    create_audit_log(db, current_admin.admin_id, 'reject_appeal', target_entity_type='Appeal', target_entity_id=id)
    db.refresh(db_appeal)
    return db_appeal

@admin_router.get("/api/admin/partners", response_model=List[APIPartner])
def get_api_partners(db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    return db.query(APIPartner).all()

@admin_router.post("/api/admin/partners", response_model=APIPartnerWithNewKey, status_code=201)
def create_api_partner(partner: APIPartnerCreate, db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    import secrets
    api_key = secrets.token_urlsafe(32)
    db_partner = APIPartner(
        organization_name=partner.organization_name,
        api_key=api_key,
        status='active'
    )
    db.add(db_partner)
    db.commit()
    create_audit_log(db, current_admin.admin_id, 'create_api_partner', details=f"Partner: {partner.organization_name}", target_entity_type='APIPartner', target_entity_id=db_partner.partner_id)
    db.refresh(db_partner)
    return db_partner

@admin_router.put("/api/admin/partners/{id}", response_model=APIPartner)
def update_api_partner(id: int, partner_update: APIPartnerUpdate, db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    db_partner = db.query(APIPartner).filter(APIPartner.partner_id == id).first()
    if not db_partner:
        raise HTTPException(status_code=404, detail="API Partner not found")
    db_partner.organization_name = partner_update.organization_name
    db_partner.status = partner_update.status
    db.commit()
    create_audit_log(db, current_admin.admin_id, 'update_api_partner', details=f"Updated partner ID {id} to status {partner_update.status}", target_entity_type='APIPartner', target_entity_id=id)
    db.refresh(db_partner)
    return db_partner

@admin_router.get("/api/admin/audit-logs", response_model=List[AuditLogEntry])
def get_audit_logs(
    date_from: Optional[datetime.date] = None,
    date_to: Optional[datetime.date] = None,
    admin_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_admin: Administrator = Depends(get_current_admin)
):
    query = db.query(AuditLog)
    if date_from:
        query = query.filter(AuditLog.action_timestamp >= date_from)
    if date_to:
        query = query.filter(AuditLog.action_timestamp <= date_to)
    if admin_id:
        query = query.filter(AuditLog.admin_id == admin_id)
    return query.order_by(AuditLog.action_timestamp.desc()).all()

@admin_router.get("/api/admin/analytics/summary", response_model=AnalyticsSummary)
def get_analytics_summary(db: Session = Depends(get_db), current_admin: Administrator = Depends(get_current_admin)):
    total_reports = db.query(Report).count()
    numbers_by_status = db.query(PhoneNumber.status, func.count(PhoneNumber.status)).group_by(PhoneNumber.status).all()
    
    trend_data = {
        "total_reports_all_time": total_reports,
        "phone_numbers_by_status": dict(numbers_by_status)
    }
    geographical_hotspots = {
        "USA": 1200,
        "India": 850,
        "UK": 430
    }
    return {"trend_data": trend_data, "geographical_hotspots": geographical_hotspots}
app.include_router(user_router)
app.include_router(admin_router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the Phone Security API"}

