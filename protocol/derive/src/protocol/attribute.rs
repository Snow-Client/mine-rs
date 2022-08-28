use proc_macro2::{Ident, Span, TokenStream};
use quote::{spanned::Spanned, ToTokens};
use syn::{
    parenthesized,
    parse::{Parse, ParseStream},
    parse2, parse_quote, Expr, LitInt, Token, Type, TypePath,
};

pub struct Attribute {
    pub span: Span,
    pub data: AttributeData,
}

#[allow(clippy::large_enum_variant)]
pub enum AttributeData {
    VarInt,
    Case(Expr),
    From(Type),
    Fixed(Fixed),
    Count(TypePath),
    StringUuid,
}
#[derive(Clone)]
pub struct Fixed {
    pub precision: u8,
    pub typ: Ident,
}
impl Parse for Fixed {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let litint: LitInt = input.parse()?;
        Ok(Fixed {
            precision: litint.base10_parse()?,
            typ: {
                let _: Token![,] = input.parse()?;
                input.parse()?
            },
        })
    }
}

pub fn parse_attr(attr: syn::Attribute) -> Option<Result<Attribute, syn::Error>> {
    let span = attr.__span();
    let tokens = attr.tokens;
    struct UnParen<T>(T);
    impl<T: Parse> Parse for UnParen<T> {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let rest;
            parenthesized!(rest in input);
            // eprintln!("attr: `{}`", (rest.fork().parse::<TokenStream>()?));
            let inner: T = rest.parse()?;
            // eprintln!("{:?}", inner.to_token_stream());
            // eprintln!("attr rest: `{}`", rest.parse::<TokenStream>()?);
            Ok(UnParen(inner))
        }
    }
    match attr.path.get_ident() {
        Some(ident) if ident == "varint" => Some(Ok(Attribute {
            span: ident.span(),
            data: AttributeData::VarInt,
        })),
        Some(ident) if ident == "stringuuid" => Some(Ok(Attribute {
            span: ident.span(),
            data: AttributeData::StringUuid,
        })),
        Some(ident) if ident == "case" => Some({
            let expr: UnParen<TokenStream> = parse_quote!(#tokens);
            parse2(expr.0).map(|expr| Attribute {
                span,
                data: AttributeData::Case(expr),
            })
        }),
        Some(ident) if ident == "from" => Some({
            let typ: UnParen<TokenStream> = parse_quote!(#tokens);
            parse2(typ.0).map(|from| Attribute {
                span,
                data: AttributeData::From(from),
            })
        }),
        Some(ident) if ident == "fixed" => Some({
            parse2::<UnParen<Fixed>>(tokens).map(|a| Attribute {
                span,
                data: AttributeData::Fixed(a.0),
            })
        }),
        Some(ident) if ident == "count" => Some({
            parse2::<UnParen<TypePath>>(tokens).map(|a| Attribute {
                span,
                data: AttributeData::Count(a.0),
            })
        }),
        _ => None,
    }
}

#[derive(Clone)]
pub enum Attrs {
    None,
    Var(Span),
    Fixed(Span, Fixed),
    FixedVar(Span, Fixed, Span),
    StringUuid(Span),
    Count(Span, TypePath),
}

pub fn struct_field(attrs: impl Iterator<Item = syn::Attribute>, res: &mut TokenStream) -> Attrs {
    let mut varint = None;
    let mut fixed = None;
    let mut stringuuid = None;
    let mut count = None;
    for attr_res in attrs.map(parse_attr) {
        let Attribute { span, data } = match attr_res {
            Some(Ok(attr)) => attr,
            Some(Err(e)) => {
                e.into_compile_error().to_tokens(res);
                continue;
            }
            None => continue,
        };
        let err_message = match data {
            AttributeData::VarInt => {
                if varint.is_none() {
                    varint = Some(span);
                    continue;
                } else {
                    "duplicate `varint` attribute on struct field"
                }
            }
            AttributeData::Case(_) => "`case` attribute not allowed to annotate struct field",
            AttributeData::From(_) => continue,
            AttributeData::Fixed(fixd) => {
                if fixed.is_none() {
                    fixed = Some((span, fixd));
                    continue;
                } else {
                    "duplicate `fixed` attribute on struct field"
                }
            }
            AttributeData::StringUuid => {
                if stringuuid.is_none() {
                    stringuuid = Some(span);
                    continue;
                } else {
                    "duplicate `stringuuid` attribute on struct field"
                }
            }
            AttributeData::Count(ty) => {
                if count.is_none() {
                    count = Some((span, ty));
                    continue;
                } else {
                    "duplicate `count` attribute on struct field"
                }
            }
        };
        error!(span, err_message).to_tokens(res)
    }
    match (varint, fixed, stringuuid, count) {
        (None, None, None, None) => Attrs::None,
        (None, None, None, Some((cs, c))) => Attrs::Count(cs, c),
        (None, None, Some(s), a) => {
            if a.is_some() {
                error!(s, "`stringuuid` incompatible with other attribute(s)").to_tokens(res);
            }
            Attrs::StringUuid(s)
        }
        (None, Some((fs, f)), a, b) => {
            if a.is_some() || b.is_some() {
                error!(fs, "`fixed` incompatible with other attribute(s)").to_tokens(res);
            }
            Attrs::Fixed(fs, f)
        }
        (Some(v), a, b, c) => {
            if a.is_some() || b.is_some() || c.is_some() {
                error!(v, "`varint` incompatible with other attribute(s)").to_tokens(res);
            }
            Attrs::Var(v)
        }
    }
}