//! The region of a declared country, for the Diversity mode.

use core::fmt;

/// A continental region. Diversity spreads a vote across regions, derived from each validator's
/// declared country.
///
/// Central America and the Caribbean belong to North America; Western Asia, including Turkey and
/// the Caucasus, belongs to Asia; Russia and Cyprus belong to Europe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Region {
    /// Africa.
    Africa,
    /// Antarctica and the sub-Antarctic islands.
    Antarctica,
    /// Asia.
    Asia,
    /// Europe.
    Europe,
    /// North America, Central America and the Caribbean.
    NorthAmerica,
    /// Oceania.
    Oceania,
    /// South America.
    SouthAmerica,
}

impl Region {
    /// The region's name, for example `North America`.
    pub const fn name(self) -> &'static str {
        match self {
            Region::Africa => "Africa",
            Region::Antarctica => "Antarctica",
            Region::Asia => "Asia",
            Region::Europe => "Europe",
            Region::NorthAmerica => "North America",
            Region::Oceania => "Oceania",
            Region::SouthAmerica => "South America",
        }
    }

    /// The region of an ISO 3166-1 alpha-2 country code, in either case (`Kosovo`'s `XK`
    /// included), or `None` for any other text.
    pub fn of_country(code: &str) -> Option<Region> {
        let code = code.trim();
        if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return None;
        }
        let lower = code.to_ascii_lowercase();
        COUNTRIES
            .iter()
            .find(|(region_codes, _)| {
                region_codes
                    .split(' ')
                    .any(|candidate| candidate == lower.as_str())
            })
            .map(|&(_, region)| region)
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// ISO 3166-1 alpha-2 codes by region, in lowercase.
const COUNTRIES: [(&str, Region); 7] = [
    (
        "ao bf bi bj bw cd cf cg ci cm cv dj dz eg eh er et ga gh gm gn gq gw ke km lr ls ly ma mg \
         ml mr mu mw mz na ne ng re rw sc sd sh sl sn so ss st sz td tg tn tz ug yt za zm zw",
        Region::Africa,
    ),
    ("aq bv hm tf", Region::Antarctica),
    (
        "ae af am az bd bh bn bt cc cn cx ge hk id il in io iq ir jo jp kg kh kp kr kw kz la lb lk \
         mm mn mo mv my np om ph pk ps qa sa sg sy th tj tl tm tr tw uz vn ye",
        Region::Asia,
    ),
    (
        "ad al at ax ba be bg by ch cy cz de dk ee es fi fo fr gb gg gi gr hr hu ie im is it je li \
         lt lu lv mc md me mk mt nl no pl pt ro rs ru se si sj sk sm ua va xk",
        Region::Europe,
    ),
    (
        "ag ai aw bb bl bm bq bs bz ca cr cu cw dm do gd gl gp gt hn ht jm kn ky lc mf mq ms mx ni \
         pa pm pr sv sx tc tt um us vc vg vi",
        Region::NorthAmerica,
    ),
    (
        "as au ck fj fm gu ki mh mp nc nf nr nu nz pf pg pn pw sb tk to tv vu wf ws",
        Region::Oceania,
    ),
    (
        "ar bo br cl co ec fk gf gs gy pe py sr uy ve",
        Region::SouthAmerica,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_once() {
        let mut codes: Vec<&str> = COUNTRIES
            .iter()
            .flat_map(|(codes, _)| codes.split(' '))
            .collect();
        assert!(codes.iter().all(|code| code.len() == 2));
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "a code is listed twice");
        // The 249 assigned codes plus XK.
        assert_eq!(total, 250);
    }

    #[test]
    fn examples() {
        assert_eq!(Region::of_country("DE"), Some(Region::Europe));
        assert_eq!(Region::of_country("de"), Some(Region::Europe));
        assert_eq!(Region::of_country(" fi "), Some(Region::Europe));
        assert_eq!(Region::of_country("US"), Some(Region::NorthAmerica));
        assert_eq!(Region::of_country("PA"), Some(Region::NorthAmerica));
        assert_eq!(Region::of_country("BR"), Some(Region::SouthAmerica));
        assert_eq!(Region::of_country("SG"), Some(Region::Asia));
        assert_eq!(Region::of_country("TR"), Some(Region::Asia));
        assert_eq!(Region::of_country("NZ"), Some(Region::Oceania));
        assert_eq!(Region::of_country("KE"), Some(Region::Africa));
        assert_eq!(Region::of_country("AQ"), Some(Region::Antarctica));
        for text in ["", "D", "DEU", "ZZ", "1A", "U S", "UK"] {
            assert_eq!(Region::of_country(text), None, "{text:?}");
        }
    }
}
