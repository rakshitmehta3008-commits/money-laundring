ntity	Attributes
EndUser
user_id: INTEGERPRIMARY KEY
email: VARCHAR(255)NOT NULLUNIQUE
password_hash: VARCHAR(255)NOT NULL
created_at: TIMESTAMPNOT NULL
PhoneNumber
phone_number_id: INTEGERPRIMARY KEY
number: VARCHAR(50)NOT NULLUNIQUE
status: VARCHAR(50)NOT NULL
ai_fraud_score: DECIMAL(5, 4)
threat_category: VARCHAR(100)
last_checked_at: TIMESTAMP
created_at: TIMESTAMPNOT NULL
Report
report_id: INTEGERPRIMARY KEY
user_id: INTEGERNOT NULLFOREIGN KEYREFERENCES EndUser(user_id)
phone_number_id: INTEGERNOT NULLFOREIGN KEYREFERENCES PhoneNumber(phone_number_id)
report_details: TEXT
submitted_at: TIMESTAMPNOT NULL
Administrator
admin_id: INTEGERPRIMARY KEY
username: VARCHAR(100)NOT NULLUNIQUE
password_hash: VARCHAR(255)NOT NULL
role: VARCHAR(50)NOT NULL
created_at: TIMESTAMPNOT NULL
API_Partner
partner_id: INTEGERPRIMARY KEY
organization_name: VARCHAR(255)NOT NULL
api_key: VARCHAR(255)NOT NULLUNIQUE
status: VARCHAR(50)NOT NULL
created_at: TIMESTAMPNOT NULL
Appeal
appeal_id: INTEGERPRIMARY KEY
phone_number_id: INTEGERNOT NULLFOREIGN KEYREFERENCES PhoneNumber(phone_number_id)
submitter_contact: VARCHAR(255)NOT NULL
appeal_reason: TEXTNOT NULL
status: VARCHAR(50)NOT NULL
reviewed_by_admin_id: INTEGERFOREIGN KEYREFERENCES Administrator(admin_id)
submitted_at: TIMESTAMPNOT NULL
reviewed_at: TIMESTAMP
AuditLog
log_id: INTEGERPRIMARY KEY
admin_id: INTEGERNOT NULLFOREIGN KEYREFERENCES Administrator(admin_id)
action: VARCHAR(255)NOT NULL
target_entity_type: VARCHAR(100)
target_entity_id: INTEGER
details: TEXT
action_timestamp: TIMESTAMPNOT NULL
UserConsent
consent_id: INTEGERPRIMARY KEY
user_id: INTEGERNOT NULLFOREIGN KEYREFERENCES EndUser(user_id)
consent_type: VARCHAR(100)NOT NULL
status: VARCHAR(50)NOT NULL
last_updated_at: TIMESTAMPNOT NULL
ScreenedCall
call_id: INTEGERPRIMARY KEY
user_id: INTEGERNOT NULLFOREIGN KEYREFERENCES EndUser(user_id)
phone_number_id: INTEGERNOT NULLFOREIGN KEYREFERENCES PhoneNumber(phone_number_id)
call_timestamp: TIMESTAMPNOT NULL
action_taken: VARCHAR(50)
alert_displayed: BOOLEANNOT NULL