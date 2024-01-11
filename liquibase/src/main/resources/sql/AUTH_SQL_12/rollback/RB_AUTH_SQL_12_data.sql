delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/refresh-token');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/authorize-resource');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/auth/api/auth/*');

delete from auth.auth_resources where resource_path = '/auth/api/auth/refresh-token';
delete from auth.auth_resources where resource_path = '/auth/api/auth/authorize-resource';
delete from auth.auth_resources where resource_path = '/auth/api/auth/*';

delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices/*');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/devices');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users/*');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/users');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures/*');
delete from auth.auth_resources_roles where resource_id = (select s.id from auth.auth_resources s where s.resource_path = '/bds/api/temperatures');

delete from auth.auth_resources where resource_path = '/bds/api/devices/*';
delete from auth.auth_resources where resource_path = '/bds/api/devices';
delete from auth.auth_resources where resource_path = '/bds/api/users/*';
delete from auth.auth_resources where resource_path = '/bds/api/users';
delete from auth.auth_resources where resource_path = '/bds/api/temperatures/*';
delete from auth.auth_resources where resource_path = '/bds/api/temperatures';