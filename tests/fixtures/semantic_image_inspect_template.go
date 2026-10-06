// Stdlib-only regression of Docker CLI typed execution then strict raw fallback.
package main
import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "text/template"
)
func main() {
 var input struct { Current string; Legacy string }
 if json.NewDecoder(io.LimitReader(os.Stdin,131072)).Decode(&input)!=nil { panic("input") }
 render := func(format string, raw map[string]any) ([]byte,error) {
  tmpl,err:=template.New("inspect").Funcs(template.FuncMap{"json":func(v any) string {b,e:=json.Marshal(v);if e!=nil {panic("json")};return string(b)}}).Parse(format)
  if err!=nil {return nil,err}
  // index on a struct Config triggers raw fallback exactly as the CLI does.
  typed:=struct {Id string;RootFS map[string]any;Config struct {User string}}{Id:"sha256:fixture",RootFS:raw["RootFS"].(map[string]any)}
  var output bytes.Buffer
  if err=tmpl.Execute(&output,typed);err!=nil {
   output.Reset();err=tmpl.Option("missingkey=error").Execute(&output,raw)
  }
  return output.Bytes(),err
 }
 root:=map[string]any{"Type":"layers","Layers":[]any{"sha256:layer"}}
 empty:=map[string]any{"Id":"sha256:fixture","RootFS":root,"Config":map[string]any{}}
 if _,err:=render(input.Legacy,empty);err==nil {panic("legacy unexpectedly accepts omitted fields")}
 cases:=[]map[string]any{
  {},
  {"User":"","WorkingDir":"","Cmd":nil,"Entrypoint":nil,"Volumes":nil},
  {"User":"1000:1000","WorkingDir":"/app","Cmd":[]any{"/app/run"},"Entrypoint":[]any{"/entry"}},
  {"Volumes":map[string]any{"/unapproved":map[string]any{}},"Env":[]any{"SECRET=never-output"}},
 }
 for i,cfg:=range cases {
  raw:=map[string]any{"Id":"sha256:fixture","RootFS":root,"Config":cfg}
  out,err:=render(input.Current,raw);if err!=nil {panic("new template fails valid optional config")}
  var v map[string]any;if json.Unmarshal(out,&v)!=nil {panic("invalid selected json")}
  if v["id"]!="sha256:fixture" || bytes.Contains(out,[]byte("never-output")) {panic("identity or secret")}
  if i<2 && (v["user"]!="" || v["workdir"]!="" || v["command"]!=nil || v["entrypoint"]!=nil || v["volumes"]!=nil) {panic("wrong empty defaults")}
  if i==2 && (v["user"]!="1000:1000" || v["workdir"]!="/app" || v["command"]==nil || v["entrypoint"]==nil) {panic("nonempty startup erased")}
  if i==3 && v["volumes"]==nil {panic("nonempty volumes erased")}
 }
 for _,key:=range []string{"Id","RootFS","Config"} {
  raw:=map[string]any{"Id":"sha256:fixture","RootFS":root,"Config":map[string]any{}}
  delete(raw,key)
  // Force strict raw map directly for missing mandatory fields.
  tmpl,_:=template.New("strict").Option("missingkey=error").Funcs(template.FuncMap{"json":func(v any) string {b,_:=json.Marshal(v);return string(b)}}).Parse(input.Current)
  if tmpl.Execute(io.Discard,raw)==nil {panic("mandatory field defaulted")}
 }
 fmt.Println("GO_IMAGE_TEMPLATE_COMPATIBILITY=PASS CASES=4 MANDATORY_FIELDS_REQUIRED=true ENV_NOT_READ=true")
}
