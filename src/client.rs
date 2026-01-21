use std::error::Error;

pub fn create_vm(_name: Option<String>, _expose: Option<u16>) -> Result<(), Box<dyn Error>> {
    todo!("implement create_vm")
}

pub fn list_vms() -> Result<(), Box<dyn Error>> {
    todo!("implement list_vms")
}

pub fn ssh_vm(_vm: &str) -> Result<(), Box<dyn Error>> {
    todo!("implement ssh_vm")
}

pub fn stop_vm(_vm: &str) -> Result<(), Box<dyn Error>> {
    todo!("implement stop_vm")
}

pub fn start_vm(_vm: &str) -> Result<(), Box<dyn Error>> {
    todo!("implement start_vm")
}

pub fn destroy_vm(_vm: &str) -> Result<(), Box<dyn Error>> {
    todo!("implement destroy_vm")
}
