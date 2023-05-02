create sequence auth.auth_users_seq start 1;
create sequence auth.auth_roles_seq start 1;

create table auth.auth_users (
    id bigint not null default nextval('auth.auth_users_seq') primary key,
    username varchar(50) not null,
    email varchar(50) not null,
    password varchar(100) not null
    --creation_date timestamp default now(),
    --last_update_date timestamp default now(),
);

create table auth.auth_roles (
    id bigint not null default nextval('auth.auth_roles_seq') primary key,
    name varchar(50)
);

create table auth.auth_users_roles (
    auth_user_id bigint not null,
    auth_role_id int not null,
    primary key(auth_user_id, auth_role_id)
);