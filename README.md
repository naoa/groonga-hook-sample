# Sample groonga hook command

## Install

Install libgroonga-dev.

Build this command.

    % ./configure
    % make
    % sudo make install

## Usage

Register `commands/hook`:

    % groonga DB
    > register commands/hook

Now, you can use `example_hook_add` and `example_hook_delete` command

```
register commands/hook
[[0,0.0,0.0],true]
table_create Entries TABLE_HASH_KEY ShortText
[[0,0.0,0.0],true]
column_create Entries title COLUMN_SCALAR ShortText
[[0,0.0,0.0],true]
column_create Entries content COLUMN_SCALAR ShortText
[[0,0.0,0.0],true]
table_create Tokens TABLE_PAT_KEY ShortText --default_tokenizer TokenBigram
[[0,0.0,0.0],true]
column_create Tokens entries_title COLUMN_INDEX|WITH_POSITION Entries title
[[0,0.0,0.0],true]
column_create Tokens entries_content COLUMN_INDEX|WITH_POSITION Entries content
[[0,0.0,0.0],true]
load --table Entries
[
{"_key": "mroonga", "title": "groonga and MySQL", "content": "groonga + MySQL = mroonga."}
]
[[0,0.0,0.0],1]
example_hook_add --table Entries --column title
[[0,0.0,0.0],[2,1,1]]
select Entries --output_columns title --command_version 2
[[0,0.0,0.0],[[[1],[["title","ShortText"]],["groonga and MySQL"]]]]
load --table Entries
[
{"_key": "rroonga", "title": "groonga and Ruby", "content": "groonga + Ruby = rroonga."}
]
[[0,0.0,0.0],1]
#|w| [hook][insert] id=2 oldvalue= value=rroonga flags=1
#|w| [hook][set] id=2 newvalue=groonga and Ruby oldvalue= flags=1
delete Entries "rroonga"
[[0,0.0,0.0],true]
#|w| [hook][delete] id=2 oldvalue=rroonga value= flags=1
#|w| [hook][set] id=2 newvalue= oldvalue=groonga and Ruby flags=1
example_hook_delete --table Entries --column title
[[0,0.0,0.0],[1,0,0]]
load --table Entries
[
{"_key": "rroonga", "title": "groonga and Ruby", "content": "groonga + Ruby = rroonga."}
]
[[0,0.0,0.0],1]
delete Entries "rroonga"
[[0,0.0,0.0],true]
```

## License

Public domain. You can copy and modify this project freely.
