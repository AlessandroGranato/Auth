create sequence auth.auth_refresh_tokens_seq start 1;

create table auth.auth_refresh_tokens (
    id bigint not null default nextval('auth.auth_refresh_tokens_seq') primary key,
    auth_user bigint not null,
    refresh_token varchar(50) not null,
    expiration_date timestamp not null,
    constraint fk_users foreign key (auth_user) references auth.auth_users (id)
);