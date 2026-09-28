//! Fitting target names into table columns.

use std::borrow::Cow;

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// `text` shortened from the left to fit `width` columns, marked with an ellipsis; the end of a
/// path or address says the most.
pub(super) fn start(text: &str, width: usize) -> Cow<'_, str> {
    if text.width() <= width {
        return Cow::Borrowed(text);
    }
    if width == 0 {
        return Cow::Borrowed("");
    }
    // The widths of the characters do not add up to the text's, for a variation selector makes
    // the character before it wider, so what is kept is measured as a whole. Names are free to
    // be all characters of no width, so how far back to look is bounded.
    let mut start = text.len();
    for (index, _) in text
        .char_indices()
        .rev()
        .take(width.saturating_mul(4).saturating_add(64))
    {
        if text[index..].width() >= width {
            break;
        }
        start = index;
    }
    // A mark whose character was cut off has nothing to attach to.
    let kept = text[start..].trim_start_matches(|c: char| c.width() == Some(0));
    Cow::Owned(format!("…{kept}"))
}

/// `path` with the home directory `home` written as `~`.
pub(super) fn tilde<'a>(path: &'a str, home: Option<&str>) -> Cow<'a, str> {
    let Some(home) = home
        .map(|home| home.trim_end_matches('/'))
        .filter(|home| !home.is_empty())
    else {
        return Cow::Borrowed(path);
    };
    match path.strip_prefix(home) {
        Some("") => Cow::Borrowed("~"),
        Some(rest) if rest.starts_with('/') => Cow::Owned(format!("~{rest}")),
        _ => Cow::Borrowed(path),
    }
}

/// `path` fitted to `width` columns. Directory names are cut to their first letter from the
/// left until it fits, which keeps the file name and the directories nearest it whole the
/// longest; when even that is too long, the start gives way.
pub(super) fn path(path: &str, width: usize) -> Cow<'_, str> {
    let mut used = path.width();
    if used <= width {
        return Cow::Borrowed(path);
    }
    let mut names: Vec<&str> = path.split('/').collect();
    let directories = names.len() - 1;
    for name in &mut names[..directories] {
        if used <= width {
            break;
        }
        // A letter can be wider alone than in the name, when a variation selector follows it.
        let cut = initial(name);
        if cut.width() >= name.width() {
            continue;
        }
        used = used.saturating_sub(name.width() - cut.width());
        *name = cut;
    }
    let shortened = names.join("/");
    if shortened.width() <= width {
        Cow::Owned(shortened)
    } else {
        Cow::Owned(start(&shortened, width).into_owned())
    }
}

/// The first letter of a directory name, after the dot of a hidden one.
fn initial(name: &str) -> &str {
    let kept = if name.starts_with('.') { 2 } else { 1 };
    match name.char_indices().nth(kept) {
        Some((end, _)) => &name[..end],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_end_of_text() {
        assert_eq!(start("/Users/me/page.html", 30), "/Users/me/page.html");
        assert_eq!(start("/Users/me/page.html", 10), "…page.html");
        assert_eq!(start("/데이터/파일", 7), "…/파일");
        assert_eq!(start("abc", 0), "");
    }

    #[test]
    fn fits_what_a_variation_selector_makes_wider() {
        // U+FE0F asks for the emoji form of a character, which takes two columns where the
        // character alone takes one, so widths of the characters do not add up to the text's.
        let hearts = "/tmp/\u{2764}\u{fe0f}\u{2764}\u{fe0f}\u{2764}\u{fe0f}\u{2764}\u{fe0f}";
        assert_eq!(hearts.width(), 13);
        for width in 1..=13 {
            assert!(start(hearts, width).width() <= width, "start to {width}");
            assert!(path(hearts, width).width() <= width, "path to {width}");
        }
        assert_eq!(start(hearts, 5), "…\u{2764}\u{fe0f}\u{2764}\u{fe0f}");
    }

    #[test]
    fn a_name_that_is_wider_alone_than_cut_short_does_not_break_the_sum() {
        // U+231A is wide, and U+FE0E asks for the text form, which is narrow: the name is one
        // column wide, and its first letter alone two.
        let watch = "\u{231a}\u{fe0e}";
        assert_eq!((watch.width(), initial(watch).width()), (1, 2));
        let long = format!("/{watch}/some/long/names/here/file.txt");
        for width in 1..=long.width() {
            assert!(path(&long, width).width() <= width, "path to {width}");
        }
    }

    #[test]
    fn writes_the_home_directory_as_a_tilde() {
        let home = Some("/Users/me");
        assert_eq!(tilde("/Users/me/Library/x", home), "~/Library/x");
        assert_eq!(tilde("/Users/me", home), "~");
        assert_eq!(tilde("/Users/me/", Some("/Users/me/")), "~/");
        assert_eq!(
            tilde("/Users/meg/x", home),
            "/Users/meg/x",
            "only whole directories"
        );
        assert_eq!(tilde("/private/tmp/x", home), "/private/tmp/x");
        assert_eq!(tilde("/Users/me/x", None), "/Users/me/x");
        assert_eq!(
            tilde("/x", Some("/")),
            "/x",
            "a home at the root is not abbreviated"
        );
    }

    #[test]
    fn cuts_directories_from_the_left() {
        let chrome = "~/Library/Application Support/Google/Chrome/Default/Cache/Cache_Data/data_1";
        assert_eq!(path(chrome, 100), chrome);
        assert_eq!(
            path(chrome, 60),
            "~/L/A/Google/Chrome/Default/Cache/Cache_Data/data_1"
        );
        assert_eq!(path(chrome, 40), "~/L/A/G/C/D/Cache/Cache_Data/data_1");
        assert_eq!(path(chrome, 25), "~/L/A/G/C/D/C/C/data_1");
        assert_eq!(path(chrome, 12), "…/C/C/data_1", "then the start gives way");
        assert_eq!(path("/.config/app/settings.json", 21), "/.c/app/settings.json");
        assert_eq!(path("/.config/app/settings.json", 20), "/.c/a/settings.json");
        assert_eq!(path("/데이터/문서/보고서.txt", 20), "/데/문서/보고서.txt");
        assert_eq!(path("/../dir/file", 11), "/../d/file", ".. stays");
        assert_eq!(path("very-long-file-name.txt", 10), "…-name.txt");
    }
}
