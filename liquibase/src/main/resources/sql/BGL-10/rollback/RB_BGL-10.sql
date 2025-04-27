delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/device/*');
delete from auth.auth_resources where resource_path = '/bds/api/temperatures/device/*';

delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/user-identifier/*');
delete from auth.auth_resources where resource_path = '/bds/api/users/user-identifier/*';

