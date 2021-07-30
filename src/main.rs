use picky::*;
use std::io::BufReader;
use std::fs::File;

fn main() {
    let leaf = File::open("C:\\Users\\aleksandr.yusuk\\Desktop\\certttts\\leaf.crt").unwrap();
    let leaf = pem::Pem::read_from(&mut BufReader::new(leaf)).unwrap();
    let leaf = x509::Cert::from_pem(&leaf).unwrap();

    let intr  = File::open("C:\\Users\\aleksandr.yusuk\\Desktop\\certttts\\inter.crt").unwrap();
    let intr = pem::Pem::read_from(&mut BufReader::new(intr)).unwrap();
    let intr = x509::Cert::from_pem(&intr).unwrap();

    let root = File::open("C:\\Users\\aleksandr.yusuk\\Desktop\\certttts\\root.crt").unwrap();
    let root = pem::Pem::read_from(&mut BufReader::new(root)).unwrap();
    let root = x509::Cert::from_pem(&root).unwrap();

    let chain = [intr, root];


    let validator = leaf.verifier();
    let now = x509::date::UTCDate::now();
    let validator = validator.exact_date(&now);
    let validator = validator.chain(chain.iter());
    validator.verify().unwrap();
}
