use picky::*;
use rsa::{PublicKey as _, RSAPublicKey};
use std::fs::File;
use std::io::BufReader;
use digest::Digest;
use std::convert::TryFrom;

fn main() {
    println!("==> manual validate");
    manual();
    println!("==> picky chain validate");
    picky();
}

fn manual() {
    let leaf =
        File::open("/home/auroden/Downloads/authenticode-psdiagnostics/3_psdiag_leaf.pem").unwrap();
    let leaf = pem::Pem::read_from(&mut BufReader::new(leaf)).unwrap();
    let tbs_der = &leaf.data()[4..1007];
    let signature = &leaf.data()[1026..1539];

    let intr = File::open("/home/auroden/Downloads/authenticode-psdiagnostics/2_psdiag_inter.pem")
        .unwrap();
    let intr = pem::Pem::read_from(&mut BufReader::new(intr)).unwrap();
    let intr = x509::Cert::from_pem(&intr).unwrap();
    let pk = intr.into_public_key();
    let pk = RSAPublicKey::try_from(&pk).unwrap();

    let digest = sha2::Sha256::digest(tbs_der).as_slice().to_vec();
    let rsa_hash_algo = rsa::Hash::SHA2_256;
    let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa_hash_algo));
    pk.verify(padding_scheme, &digest, signature).unwrap();
}

fn picky() {
    let leaf =
        File::open("/home/auroden/Downloads/authenticode-psdiagnostics/3_psdiag_leaf.pem").unwrap();
    let leaf = pem::Pem::read_from(&mut BufReader::new(leaf)).unwrap();
    let leaf = x509::Cert::from_pem(&leaf).unwrap();

    let intr = File::open("/home/auroden/Downloads/authenticode-psdiagnostics/2_psdiag_inter.pem")
        .unwrap();
    let intr = pem::Pem::read_from(&mut BufReader::new(intr)).unwrap();
    let intr = x509::Cert::from_pem(&intr).unwrap();

    let root =
        File::open("/home/auroden/Downloads/authenticode-psdiagnostics/1_psdiag_root.pem").unwrap();
    let root = pem::Pem::read_from(&mut BufReader::new(root)).unwrap();
    let root = x509::Cert::from_pem(&root).unwrap();

    let chain = [intr, root];

    let validator = leaf.verifier();
    let now = x509::date::UTCDate::now();
    let validator = validator.exact_date(&now);
    let validator = validator.chain(chain.iter());
    validator.verify().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_validate() {
        manual();
    }

    #[test]
    fn picky_chain_validate() {
        picky();
    }

    #[test]
    fn picky_vs_original_der() {
        use picky_asn1_x509::Certificate;

        let leaf =
            File::open("/home/auroden/Downloads/authenticode-psdiagnostics/3_psdiag_leaf.pem")
                .unwrap();
        let leaf = pem::Pem::read_from(&mut BufReader::new(leaf)).unwrap();
        let original_der = leaf.data()[4..1007].to_vec();
        let leaf = Certificate::from(x509::Cert::from_pem(&leaf).unwrap());
        let picky_der = picky_asn1_der::to_vec(&leaf.tbs_certificate).unwrap();
        assert_eq!(original_der, picky_der);
    }
}
