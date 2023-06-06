create sequence auth.auth_resources_seq start 1;
create sequence auth.auth_resources_roles_seq start 1;

create table auth.auth_resources (
    id bigint not null default nextval('auth.auth_resources_seq') primary key,
    resource_path varchar(50) not null
);

create table auth.auth_resources_roles (
    resource_id bigint not null,
    auth_role_id int not null,
    primary key(resource_id, auth_role_id),
    constraint fk_resources foreign key (resource_id) references auth.auth_resources (id),
    constraint fk_roles foreign key (auth_role_id) references auth.auth_roles (id)
);