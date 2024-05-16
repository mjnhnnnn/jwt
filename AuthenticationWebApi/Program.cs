global using AuthenticationWebApi.Models;
global using AuthenticationWebApi.Services.AuthService;
global using Microsoft.EntityFrameworkCore;
global using AuthenticationWebApi.Data;
global using Microsoft.IdentityModel.Tokens;
using Microsoft.Data.SqlClient;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using AuthenticationWebApi.RefreshTokenMiddleware;
using Microsoft.AspNetCore.Builder;

var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddPolicy(MyAllowSpecificOrigins,
                          policy =>
                          {
                              policy.WithOrigins("http://localhost:3000", "http://localhost:3001")
                                                  .AllowAnyHeader()
                                                  .AllowAnyMethod().AllowCredentials();
                          });
});

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Description = "Standard Authorization Header using the Bearer scheme (\"Bearer {token}\")",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});
builder.Services.AddScoped<IAuthService, AuthService>();

builder.Services.AddDbContext<DataContext>(options => options.UseSqlServer(
    builder.Configuration.GetConnectionString("DefaultCon")
    ));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8
            .GetBytes(builder.Configuration.GetSection("AppSettings:Token").Value)),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});
builder.Services.AddHttpContextAccessor();

var app = builder.Build();
app.UseCors(MyAllowSpecificOrigins);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//var ignoredPaths = new List<string> { "/api/Auth/refresh-token", "/api/Auth/login" };

//foreach (var path in ignoredPaths)
//{
//    app.MapWhen(context => !context.Request.Path.StartsWithSegments(path),
//        builder => builder.UseMiddleware<RefreshTokenMiddleware>());
//}

app.UseHttpsRedirection();

//app.UseAuthentication();

//app.UseAuthorization();


app.UseRouting();
app.UseMiddleware<RefreshTokenMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

//var ignoredPaths = new List<string> { "/api/Auth/refresh-token", "/api/Auth/login" };
//app.MapWhen(context => !ignoredPaths.Contains(context.Request.Path.Value), builder =>
//{
//    builder.UseMiddleware<RefreshTokenMiddleware>();
//});

//app.UseEndpoints(endpoints =>
//{
//    endpoints.MapControllers();
//});



app.MapControllers();

//app.Run(context => { context.Response.Redirect("swagger"); return Task.CompletedTask; });
app.Run();
