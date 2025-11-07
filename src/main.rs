use quote::ToTokens;
use std::env::args;
use std::fs;
use syn::{
    AngleBracketedGenericArguments, Expr, Fields, GenericArgument, GenericParam, Generics, Item,
    ItemEnum, ItemStruct, ItemUnion, Lit, PathArguments, Type, TypeArray, TypePath, TypePtr,
    TypeReference, TypeSlice, TypeTuple, UnOp,
};
fn main() {
    for arg in args().skip(1) {
        if let Ok(iter) = fs::read_dir(&arg) {
            for file in iter {
                let strings = parse_from_file(file.unwrap().path().to_str().unwrap());
                for s in strings {
                    println!("{s}");
                }
            }
        } else {
            let strings = parse_from_file(&arg);
            for s in strings {
                println!("{s}");
            }
        }
    }
}
fn parse_generics(generics: &Generics) -> String {
    let generics = generics
        .params
        .iter()
        .filter_map(|g| match g {
            GenericParam::Lifetime(_) => None,
            GenericParam::Type(ty) => Some(ty.ident.to_string()),
            GenericParam::Const(id) => Some(id.ident.to_string()),
        })
        .collect::<Vec<String>>();
    if generics.is_empty() {
        String::new()
    } else {
        format!("<{}>", generics.join(","))
    }
}
fn parse_type(ty: &Type) -> String {
    match ty {
        Type::Array(TypeArray { elem, len, .. }) => {
            format!("[{};{}]", parse_type(elem), parse_len(len))
        }
        Type::Ptr(TypePtr { elem, .. }) => {
            format!("*{}", parse_type(elem))
        }
        Type::Reference(TypeReference { elem, .. }) => {
            format!("*{}", parse_type(elem))
        }
        Type::Slice(TypeSlice { elem, .. }) => {
            format!("[{}]", parse_type(elem))
        }
        Type::Tuple(TypeTuple { elems, .. }) => {
            format!(
                "({})",
                elems
                    .iter()
                    .map(parse_type)
                    .collect::<Vec<String>>()
                    .join(",")
            )
        }
        Type::Path(TypePath { path, .. }) => {
            let last = path.segments.last().unwrap();
            if last.arguments.is_empty() {
                last.ident.to_string()
            } else if let PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                args,
                ..
            }) = &last.arguments
            {
                format!(
                    "{}<{}>",
                    last.ident,
                    args.iter()
                        .map(|g| match g {
                            GenericArgument::Type(ty) => {
                                parse_type(ty)
                            }
                            GenericArgument::Const(expr) => {
                                parse_len(expr)
                            }
                            _ => todo!(),
                        })
                        .collect::<Vec<String>>()
                        .join(",")
                )
            } else {
                String::new()
            }
        }
        _ => todo!(),
    }
}
fn parse_len(ex: &Expr) -> String {
    match ex {
        Expr::Lit(lit) => match &lit.lit {
            Lit::Int(int) => int
                .base10_parse::<isize>()
                .map_or_else(|_| ex.to_token_stream().to_string(), |v| v.to_string()),
            _ => todo!(),
        },
        Expr::Binary(bin) => {
            let Ok(l) = parse_len(&bin.left).parse::<isize>() else {
                return String::new();
            };
            let Ok(r) = parse_len(&bin.right).parse::<isize>() else {
                return String::new();
            };
            let op = bin.op.to_token_stream().to_string();
            match op.as_str() {
                "*" => l * r,
                "/" => l / r,
                "+" => l + r,
                "-" => l - r,
                "%" => l % r,
                _ => todo!(),
            }
            .to_string()
        }
        Expr::Unary(unary) => match unary.op {
            UnOp::Neg(_) => {
                format!("-{}", parse_len(&unary.expr))
            }
            _ => todo!(),
        },
        Expr::Path(path) => path.path.segments.last().unwrap().ident.to_string(),
        _ => todo!(),
    }
}
fn parse_from_file(path: &str) -> Vec<String> {
    let src = fs::read_to_string(path).unwrap();
    let syntax = syn::parse_file(&src).unwrap();
    syntax
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Struct(s) => Some(parse_struct(s)),
            Item::Union(u) => Some(parse_union(u)),
            Item::Enum(e) => Some(parse_enum(e)),
            _ => None,
        })
        .collect()
}
fn parse_struct(item_struct: ItemStruct) -> String {
    let mut s = format!(
        "struct {}{}",
        item_struct.ident,
        parse_generics(&item_struct.generics)
    );
    for (i, field) in item_struct.fields.iter().enumerate() {
        if let Some(ident) = &field.ident {
            s += &format!(" {ident}:{}", parse_type(&field.ty))
        } else {
            s += &format!(" f{i}:{}", parse_type(&field.ty))
        }
    }
    s
}
fn parse_enum(item_enum: ItemEnum) -> String {
    let mut s = format!(
        "enum {}{}",
        item_enum.ident,
        parse_generics(&item_enum.generics)
    );
    let mut i = 0;
    for var in &item_enum.variants {
        if let Some(d) = &var.discriminant {
            s += &format!(
                " {}{}:{}",
                var.ident,
                parse_field(&var.fields),
                parse_len(&d.1)
            )
        } else {
            s += &format!(" {}{}:{i}", var.ident, parse_field(&var.fields));
            i += 1;
        }
    }
    s
}
fn parse_union(item_union: ItemUnion) -> String {
    let mut s = format!(
        "union {}{}",
        item_union.ident,
        parse_generics(&item_union.generics)
    );
    for field in item_union.fields.named {
        if let Some(ident) = &field.ident {
            s += &format!(" {ident}:{}", parse_type(&field.ty))
        }
    }
    s
}
fn parse_field(fields: &Fields) -> String {
    match fields {
        Fields::Named(named) => {
            format!(
                "({})",
                named
                    .named
                    .iter()
                    .map(|a| format!("{}: {}", a.ident.as_ref().unwrap(), parse_type(&a.ty)))
                    .collect::<String>()
            )
        }
        Fields::Unnamed(unnamed) => {
            format!(
                "({})",
                unnamed
                    .unnamed
                    .iter()
                    .map(|a| parse_type(&a.ty))
                    .collect::<String>()
            )
        }
        Fields::Unit => String::new(),
    }
}
