use crate::utils::generate_large_init_contract;
use foundry_compilers::artifacts::BytecodeHash;
use foundry_config::Config;
use foundry_test_utils::forgetest;

forgetest_init!(can_build_with_revive, |prj, cmd| {
    prj.write_config(Config { bytecode_hash: BytecodeHash::None, ..Default::default() });
    cmd.args(["build", "--revive-compile"]).assert_success();
});

forgetest_init!(force_buid_with_revive, |prj, cmd| {
    prj.write_config(Config { bytecode_hash: BytecodeHash::None, ..Default::default() });
    cmd.args(["build", "--revive-compile", "--force"]).assert_success();
});
/* This test wont work as expected since revive produces much larger bytecode than solc
forgetest!(initcode_size_limit_can_be_ignored_revive, |prj, cmd| {
    prj.write_config(Config { bytecode_hash: BytecodeHash::None, ..Default::default() });
    prj.add_source("LargeContract", generate_large_init_contract(50_000).as_str()).unwrap();
    cmd.args(["build", "--revive-compile", "--sizes", "--ignore-eip-3860"]).assert_success();
});
*/
