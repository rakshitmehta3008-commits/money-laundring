- Create the database

CREATE TABLE EndUser (
    
    user_id INTEGER 
    PRIMARY KEY,
    email VARCHAR(
    255
) NOT NULL UNIQUE,
    password_hash VARCHAR(
    255
) NOT NULL,
    created_at TIMESTAMP NOT NULL

);



CREATE TABLE PhoneNumber (
    
    phone_number_id INTEGER 
    PRIMARY KEY,
    number VARCHAR(
    50
) NOT NULL UNIQUE,
    status VARCHAR(
    50
) NOT NULL,
    ai_fraud_score DECIMAL(
    5, 4
),
    threat_category VARCHAR(
    100
),
    last_checked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL

);


CREATE TABLE Administrator (
    
    admin_id INTEGER 
    PRIMARY KEY,
    username VARCHAR(
    100
) NOT NULL UNIQUE,
    password_hash VARCHAR(
    255
) NOT NULL,
    role VARCHAR(
    50
) NOT NULL,
    created_at TIMESTAMP NOT NULL

);

CREATE TABLE API_Partner (
    
    partner_id INTEGER 
    PRIMARY KEY,
    organization_name VARCHAR(
    255
) NOT NULL,
    api_key VARCHAR(
    255
) NOT NULL UNIQUE,
    status VARCHAR(
    50
) NOT NULL,
    created_at TIMESTAMP NOT NULL

);

CREATE TABLE Report (
    
    report_id INTEGER 
    PRIMARY KEY,
    user_id INTEGER NOT NULL,
    phone_number_id INTEGER NOT NULL,
    report_details TEXT,
    submitted_at TIMESTAMP NOT NULL,
    FOREIGN KEY (
    user_id
) REFERENCES EndUser(
    user_id
),
    FOREIGN KEY (
    phone_number_id
) REFERENCES PhoneNumber(
    phone_number_id
)

);

CREATE TABLE Appeal (
    
    appeal_id INTEGER 
    PRIMARY KEY,
    phone_number_id INTEGER NOT NULL,
    submitter_contact VARCHAR(
    255
) NOT NULL,
    appeal_reason TEXT NOT NULL,
    status VARCHAR(
    50
) NOT NULL,
    reviewed_by_admin_id INTEGER,
    submitted_at TIMESTAMP NOT NULL,
    reviewed_at TIMESTAMP,
    FOREIGN KEY (
    phone_number_id
) REFERENCES PhoneNumber(
    phone_number_id
),
    FOREIGN KEY (
    reviewed_by_admin_id
) REFERENCES Administrator(
    admin_id
)

);

CREATE TABLE AuditLog (
    
    log_id INTEGER 
    PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    action VARCHAR(
    255
) NOT NULL,
    target_entity_type VARCHAR(
    100
),
    target_entity_id INTEGER,
    details TEXT,
    action_timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (
    admin_id
) REFERENCES Administrator(
    admin_id
)

);

CREATE TABLE UserConsent (
    
    consent_id INTEGER 
    PRIMARY KEY,
    user_id INTEGER NOT NULL,
    consent_type VARCHAR(
    100
) NOT NULL,
    status VARCHAR(
    50
) NOT NULL,
    last_updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (
    user_id
) REFERENCES EndUser(
    user_id
)

);

CREATE TABLE ScreenedCall (
    
    call_id INTEGER 
    PRIMARY KEY,
    user_id INTEGER NOT NULL,
    phone_number_id INTEGER NOT NULL,
    call_timestamp TIMESTAMP NOT NULL,
    action_taken VARCHAR(
    50
),
    alert_displayed BOOLEAN NOT NULL,
    FOREIGN KEY (
    user_id
) REFERENCES EndUser(
    user_id
),
    FOREIGN KEY (
    phone_number_id
) REFERENCES PhoneNumber(
    phone_number_id
)

);