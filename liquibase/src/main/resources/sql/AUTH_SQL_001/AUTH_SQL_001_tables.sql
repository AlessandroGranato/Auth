CREATE SEQUENCE auth.auth_user_seq START 101;
CREATE TABLE auth.AUTH_USER (
    ID BIGINT not null default nextval('auth.auth_user_seq') primary key,
    USERNAME VARCHAR(25) not null,
    EMAIL VARCHAR(25) not null,
    PASSWORD VARCHAR(100) not null
    CREATION_DATE TIMESTAMP default now(),
    LAST_UPDATE_DATE TIMESTAMP default now(),
);