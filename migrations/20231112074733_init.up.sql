-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE 
    "users" (
      id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) NOT NULL,
      photo VARCHAR NOT NULL DEFAULT 'https://res.cloudinary.com/trade-grid/image/upload/v1618526995/default_profile_pic_pwfk1s.png',
      verified BOOLEAN NOT NULL DEFAULT false,
      password VARCHAR(100) NOT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'user',
      created_at TIMESTAMP
      WITH 
          TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP 
      WITH 
          TIME ZONE DEFAULT NOW()    
    );

 CREATE INDEX user_email_idx ON users (email);   
