using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

public class AntiForgeryTokenHeaderParameter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        if (context.ApiDescription.ActionDescriptor.DisplayName.Contains("/upload/safe"))
        {
            operation.Parameters =
            [
                new OpenApiParameter
                {
                    Name = "RequestVerificationToken",
                    In = ParameterLocation.Header,
                    Description = "AntiForgeryToken",
                    Required = true
                },
            ];
        }
    }
}