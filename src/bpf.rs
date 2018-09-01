use tera::{Context, Tera}
pub get_kmalloc_kfree_bpf(pids: &Vec<String>) -> Result<String, Error>{
    let tera = Tera::new("./");
    let mut ctx = Context::new();
    ctx.add("pids", pids);
    let rendered = tera.render("kmalloc_kfree.c", ctx)?;
}